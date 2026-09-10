// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/dedup"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/falcon"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// QueueSize is the capacity of the batch channel between the reader and writer.
// The bounded buffer provides producer backpressure: the reader blocks once the
// writer falls this many batches behind.
const QueueSize = 10

// IndicatorSource streams pages of indicators from an upstream intel API,
// beginning at a cursor and invoking fn once per non-empty page with the marker
// that follows it. The Falcon client satisfies this interface; tests supply a
// fake.
type IndicatorSource interface {
	Stream(ctx context.Context, cur falcon.Cursor, fn func(page []indicator.Indicator, lastMarker string) error) error
}

// ReaderConfig holds the collaborators and cadence a Reader needs.
type ReaderConfig struct {
	Source    IndicatorSource
	Cache     *dedup.Cache
	Frequency time.Duration
	Start     falcon.Cursor
}

// Reader polls the indicator source on a fixed cadence, reshapes and
// deduplicates each page, and forwards the survivors as batches. It advances an
// in-memory cursor so each cycle resumes exactly where the last one ended.
//
// replaying records whether the previous cycle failed to deliver, so the current
// cycle is re-fetching an undelivered window. Recovery relies on the dedup cache
// to suppress re-sending indicators that were delivered before the failure; that
// only holds while those entries remain in the cache, so a replay window larger
// than the cache size can evict them and cause duplicate delivery. The flag lets
// the reader warn when that happens. It is touched only by the reader goroutine.
type Reader struct {
	source    IndicatorSource
	cache     *dedup.Cache
	frequency time.Duration
	cursor    falcon.Cursor
	replaying bool
}

// NewReader returns a Reader configured from cfg.
func NewReader(cfg ReaderConfig) *Reader {
	return &Reader{
		source:    cfg.Source,
		cache:     cfg.Cache,
		frequency: cfg.Frequency,
		cursor:    cfg.Start,
	}
}

// cycleStats records what a single fetch cycle produced, for logging.
type cycleStats struct {
	received int
	sent     int
	skipped  int
}

// Run drives fetch cycles until ctx is cancelled, sending each batch of new
// indicators on out and sleeping frequency between cycles. Run owns out and
// closes it on return, signalling the writer to drain and stop. A cancelled
// context is a clean shutdown and yields a nil error.
func (r *Reader) Run(ctx context.Context, out chan<- Batch) error {
	defer close(out)
	for {
		stats, err := r.cycle(ctx, out)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}

		cacheStats := r.cache.Stats()
		slog.Info("fetch cycle complete",
			"component", "reader",
			"received", stats.received,
			"sent", stats.sent,
			"skipped", stats.skipped,
			"cache_size", cacheStats.Size,
			"cache_evictions", cacheStats.Evictions,
		)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.frequency):
		}
	}
}

// cycle streams one full pass of the source starting at the current cursor,
// forwarding batches of undeduplicated indicators. After the pass it drains the
// writer with a flush sentinel and picks the next cursor from what was actually
// delivered: on a clean cycle it advances to the last marker seen (or to the
// cycle start time when the pass yielded no marker); on a failed cycle it holds
// at the last delivered marker so the undelivered window is re-fetched next
// cycle, giving a gapless, loss-free resume.
func (r *Reader) cycle(ctx context.Context, out chan<- Batch) (cycleStats, error) {
	cycleStart := time.Now()
	evictionsBefore := r.cache.Stats().Evictions
	var stats cycleStats
	var lastMarkerSeen string

	err := r.source.Stream(ctx, r.cursor, func(page []indicator.Indicator, marker string) error {
		if marker != "" {
			lastMarkerSeen = marker
		}

		toSend := make([]indicator.Indicator, 0, len(page))
		for _, ind := range page {
			transform(ind)
			if !r.cache.Seen(ind) {
				toSend = append(toSend, ind)
			}
		}

		stats.received += len(page)
		stats.sent += len(toSend)
		stats.skipped += len(page) - len(toSend)

		if len(toSend) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- Batch{Indicators: toSend, Marker: marker}:
			return nil
		}
	})
	if err != nil {
		return stats, err
	}

	report, err := r.flush(ctx, out)
	if err != nil {
		return stats, err
	}

	// When this cycle was re-fetching an undelivered window, dedup entries
	// evicted during the pass may have belonged to already-delivered indicators,
	// which are then re-sent as duplicates. Warn so an operator can raise the
	// cache size if the replay window routinely exceeds it.
	if r.replaying {
		if after := r.cache.Stats(); after.Evictions > evictionsBefore {
			slog.Warn("dedup entries evicted while replaying undelivered indicators; already-delivered indicators may be re-sent to chronicle",
				"component", "reader",
				"evicted", after.Evictions-evictionsBefore,
			)
		}
	}
	r.replaying = report.failed

	switch {
	case report.failed && report.committed != "":
		// A delivery failed: resume from the last batch fully delivered so the
		// undelivered window is re-fetched, rather than skipped past.
		r.cursor = falcon.FromMarker(report.committed)
	case report.failed:
		// A delivery failed before any batch committed (e.g. cold start with no
		// prior marker): keep the current cursor so the same window is
		// re-fetched, rather than advancing time past undelivered data.
	case lastMarkerSeen != "":
		r.cursor = falcon.FromMarker(lastMarkerSeen)
	default:
		r.cursor = falcon.FromTime(cycleStart.Unix())
	}
	return stats, nil
}

// flush sends the end-of-cycle barrier sentinel and waits for the writer's
// report of where delivery reached. The sentinel is FIFO-ordered behind the
// cycle's data batches on the same channel, so the report reflects a settled
// state with nothing in flight. Both the send and the receive honor ctx so a
// shutdown cannot block the reader or leak the writer goroutine.
func (r *Reader) flush(ctx context.Context, out chan<- Batch) (deliveryReport, error) {
	reply := make(chan deliveryReport, 1)
	select {
	case <-ctx.Done():
		return deliveryReport{}, ctx.Err()
	case out <- Batch{flush: reply}:
	}
	select {
	case <-ctx.Done():
		return deliveryReport{}, ctx.Err()
	case report := <-reply:
		return report, nil
	}
}
