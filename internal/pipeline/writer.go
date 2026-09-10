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
	"log/slog"
	"time"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// chunkSize is the maximum number of indicators sent to Chronicle in one call;
// larger batches are split into chunks of this size.
const chunkSize = 250

// maxSendAttempts bounds the retries for a single chunk before the writer gives
// up and declines to advance the marker past undelivered data.
const maxSendAttempts = 30

// sessionResetAttempt is the retry index at which the writer rebuilds the sink's
// session, recovering from a wedged connection or a stale token.
const sessionResetAttempt = 5

// maxBackoff caps the exponential backoff between send retries.
const maxBackoff = 60 * time.Second

// Sink delivers a chunk of indicators to the downstream store and can rebuild
// its session after repeated failures. The Chronicle client satisfies this
// interface; tests supply a fake.
type Sink interface {
	Send(ctx context.Context, batch []indicator.Indicator) error
	ResetSession()
}

// MarkerStore persists the resume marker once a batch is fully delivered.
type MarkerStore interface {
	Save(marker string) error
}

// Recorder remembers indicators that have been accepted downstream so they are
// suppressed on a later fetch. The dedup cache satisfies this interface.
type Recorder interface {
	Record(ind indicator.Indicator)
}

// WriterConfig holds the collaborators a Writer needs.
type WriterConfig struct {
	Sink  Sink
	State MarkerStore
	Dedup Recorder
}

// Writer consumes batches, delivers them to the sink in bounded chunks with
// retry, records delivered indicators for dedup, and persists each batch's
// marker only after every chunk succeeds and no earlier batch in the cycle
// failed, so the persisted cursor never advances past undelivered data.
//
// committed and failed are touched only by the writer goroutine, so they need
// no lock. committed is the marker of the last batch fully delivered without a
// preceding failure; it persists across cycles and is reported to the reader at
// each cycle's flush sentinel. failed records whether any delivery failed since
// the last flush and is reset once the sentinel is answered.
type Writer struct {
	sink      Sink
	state     MarkerStore
	dedup     Recorder
	committed string
	failed    bool
}

// NewWriter returns a Writer configured from cfg.
func NewWriter(cfg WriterConfig) *Writer {
	return &Writer{sink: cfg.Sink, state: cfg.State, dedup: cfg.Dedup}
}

// Run delivers batches from in until the channel is closed and drained, then
// returns. Closing the channel is the reader's shutdown signal; ranging over it
// lets in-flight batches finish before the writer exits.
//
// A batch with a non-nil flush is the reader's end-of-cycle barrier, not data:
// the writer answers with the marker of the last batch delivered before any
// failure this cycle and whether a delivery failed, then clears the per-cycle
// failure flag. Because the sentinel arrives after the cycle's data batches on
// the same channel, every batch has already been processed when it is answered,
// so the report reflects a settled state with nothing in flight. The reply and
// its send both honor ctx so a shutdown mid-flush cannot leak this goroutine.
func (w *Writer) Run(ctx context.Context, in <-chan Batch) error {
	for batch := range in {
		if batch.flush != nil {
			select {
			case batch.flush <- deliveryReport{committed: w.committed, failed: w.failed}:
			case <-ctx.Done():
				return nil
			}
			w.failed = false
			continue
		}
		w.deliver(ctx, batch)
	}
	return nil
}

// deliver sends every chunk of a batch, records each indicator for dedup only
// after its chunk is accepted, and advances the committed marker only once
// every chunk succeeds. A failed chunk marks the cycle failed and aborts the
// batch without recording its indicators or advancing the marker.
//
// Once a batch has failed this cycle, no later batch advances the committed
// marker or persists it, even if that later batch succeeds: the resume position
// is frozen at the last batch delivered before the first failure. This holds the
// reader's next-cycle cursor and the persisted marker at the same point, so the
// undelivered window is re-fetched — in-process on the next cycle and after a
// restart from the persisted marker — rather than skipped. Any re-delivered
// indicator that did land is suppressed by dedup.
func (w *Writer) deliver(ctx context.Context, b Batch) {
	for start := 0; start < len(b.Indicators); start += chunkSize {
		end := min(start+chunkSize, len(b.Indicators))
		chunk := b.Indicators[start:end]
		if !w.sendChunk(ctx, chunk) {
			w.failed = true
			return
		}
		for _, ind := range chunk {
			w.dedup.Record(ind)
		}
	}

	if w.failed || b.Marker == "" {
		return
	}
	w.committed = b.Marker
	if err := w.state.Save(b.Marker); err != nil {
		slog.Error("could not persist resume marker", "component", "writer", "marker", b.Marker, "error", err)
	}
}

// sendChunk delivers one chunk, retrying up to maxSendAttempts with exponential
// backoff and rebuilding the sink session at sessionResetAttempt. It reports
// whether the chunk was accepted. Delivery uses a context detached from ctx so a
// shutdown in progress can still flush a final attempt; the backoff wait honors
// ctx so shutdown stops the retry loop promptly.
func (w *Writer) sendChunk(ctx context.Context, chunk []indicator.Indicator) bool {
	sendCtx := context.WithoutCancel(ctx)
	for attempt := range maxSendAttempts {
		err := w.sink.Send(sendCtx, chunk)
		if err == nil {
			return true
		}
		slog.Error("chronicle send failed; will retry",
			"component", "writer",
			"attempt", attempt+1,
			"of", maxSendAttempts,
			"count", len(chunk),
			"error", err,
		)

		if attempt == sessionResetAttempt {
			w.sink.ResetSession()
		}

		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoffFor(attempt)):
		}
	}

	slog.Error("could not transmit indicators to chronicle after all attempts",
		"component", "writer",
		"attempts", maxSendAttempts,
		"count", len(chunk),
	)
	return false
}

// backoffFor returns the delay before the given retry attempt: 2^attempt
// seconds, capped at maxBackoff.
func backoffFor(attempt int) time.Duration {
	d := time.Duration(1<<attempt) * time.Second
	if d <= 0 || d > maxBackoff {
		return maxBackoff
	}
	return d
}
