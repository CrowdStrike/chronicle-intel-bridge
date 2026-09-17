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

	"github.com/crowdstrike/chronicle-intel-bridge/internal/chronicle"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// chunkSize is the maximum number of indicators sent to Chronicle in one call;
// larger batches are split into chunks of this size. The sink splits further by
// encoded size when a chunk would exceed Chronicle's request-size limit, so this
// is a count bound only.
const chunkSize = 250

// maxSendAttempts bounds the retries for a single chunk before the writer gives
// up and declines to advance the marker past undelivered data.
const maxSendAttempts = 30

// sessionResetAttempt is the retry index at which the writer rebuilds the sink's
// session, recovering from a wedged connection or a stale token.
const sessionResetAttempt = 5

// maxBackoff caps the exponential backoff between send retries.
const maxBackoff = 60 * time.Second

// rateLimitMinBackoff is the floor applied to the retry wait after a rate-limited
// response. The import API requires a minimum delay of 30 seconds before retrying
// an HTTP 429, which is longer than the early exponential-backoff steps, so a 429
// retry waits at least this long.
const rateLimitMinBackoff = 30 * time.Second

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
// marker only once the batch is resolved and no earlier batch in the cycle was
// left undelivered, so the persisted cursor never advances past data that was
// neither delivered nor deliberately dropped.
//
// A chunk the sink rejects as permanently unacceptable is dropped — logged and
// recorded for dedup — rather than retried or held back, so one malformed or
// forbidden indicator cannot wedge the pipeline behind it forever. Only a chunk
// left undelivered by exhausted retries or shutdown holds the marker back.
//
// committed and failed are touched only by the writer goroutine, so they need
// no lock. committed is the marker of the last batch fully resolved without a
// preceding undelivered chunk; it persists across cycles and is reported to the
// reader at each cycle's flush sentinel. failed records whether any chunk was
// left undelivered since the last flush and is reset once the sentinel is
// answered. backoff computes the wait between send retries and is a field so a
// test can inject a zero delay and exercise the retry paths without real waits.
type Writer struct {
	sink      Sink
	state     MarkerStore
	dedup     Recorder
	backoff   func(attempt int, err error) time.Duration
	committed string
	failed    bool
}

// NewWriter returns a Writer configured from cfg.
func NewWriter(cfg WriterConfig) *Writer {
	return &Writer{sink: cfg.Sink, state: cfg.State, dedup: cfg.Dedup, backoff: retryDelay}
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

// sendOutcome is the result of delivering one chunk to the sink.
type sendOutcome int

const (
	// chunkAccepted means the sink accepted the chunk.
	chunkAccepted sendOutcome = iota
	// chunkRejected means the sink refused the chunk as permanently unacceptable:
	// an identical retry cannot succeed, so the chunk is dropped rather than held
	// back to be re-fetched forever.
	chunkRejected
	// chunkUndelivered means the chunk was not accepted before retries were
	// exhausted or shutdown interrupted the loop: it may yet succeed, so the
	// marker is held back to re-fetch it.
	chunkUndelivered
)

// deliver sends every chunk of a batch and advances the committed marker once
// the batch is resolved. A chunk that is accepted, and a chunk the sink rejects
// as permanently unacceptable, are both recorded for dedup and the batch
// continues: the rejected chunk is logged and dropped, since retrying or
// re-fetching a request the server has already refused as malformed or forbidden
// only stalls the pipeline behind data it will never accept. A chunk left
// undelivered by exhausted retries or shutdown, by contrast, marks the cycle
// failed and aborts the batch without advancing the marker.
//
// Once a batch has been left undelivered this cycle, no later batch advances the
// committed marker or persists it, even if that later batch succeeds: the resume
// position is frozen at the last batch resolved before the first undelivered
// chunk. This holds the reader's next-cycle cursor and the persisted marker at
// the same point, so the undelivered window is re-fetched — in-process on the
// next cycle and after a restart from the persisted marker — rather than skipped.
// Any re-delivered indicator that did land is suppressed by dedup.
func (w *Writer) deliver(ctx context.Context, b Batch) {
	for start := 0; start < len(b.Indicators); {
		end := min(start+chunkSize, len(b.Indicators))
		chunk := b.Indicators[start:end]

		outcome, err := w.sendChunk(ctx, chunk)
		if outcome == chunkUndelivered {
			w.failed = true
			return
		}
		if outcome == chunkRejected {
			logRejectedChunk(chunk, err)
		}
		for _, ind := range chunk {
			w.dedup.Record(ind)
		}
		start = end
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
// whether the chunk was accepted, permanently rejected, or left undelivered, and
// returns the error behind a non-accepted outcome. A permanent rejection aborts
// the chunk at once, since re-sending an identical request the server has already
// rejected as malformed or forbidden cannot succeed. Delivery uses a context
// detached from ctx so a shutdown in progress can still flush a final attempt;
// the backoff wait honors ctx so shutdown stops the retry loop promptly.
func (w *Writer) sendChunk(ctx context.Context, chunk []indicator.Indicator) (sendOutcome, error) {
	sendCtx := context.WithoutCancel(ctx)
	var err error
	for attempt := range maxSendAttempts {
		err = w.sink.Send(sendCtx, chunk)
		if err == nil {
			return chunkAccepted, nil
		}
		if errors.Is(err, chronicle.ErrPermanent) {
			return chunkRejected, err
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
			return chunkUndelivered, err
		case <-time.After(w.backoff(attempt, err)):
		}
	}

	slog.Error("could not transmit indicators to chronicle after all attempts",
		"component", "writer",
		"attempts", maxSendAttempts,
		"count", len(chunk),
	)
	return chunkUndelivered, err
}

// logRejectedChunk records that a permanently rejected chunk is being dropped
// instead of delivered, naming each indicator by id and carrying the sink's
// error so the drop is auditable. The ids are operational identifiers, not
// secrets, so they may appear in logs.
func logRejectedChunk(chunk []indicator.Indicator, err error) {
	ids := make([]string, 0, len(chunk))
	for _, ind := range chunk {
		if id, ok := ind["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	slog.Error("chronicle permanently rejected indicators; dropping them and advancing past the rejected window",
		"component", "writer",
		"count", len(chunk),
		"indicator_ids", ids,
		"error", err,
	)
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

// retryDelay returns how long to wait before the next retry of a failed send:
// the exponential backoff for the attempt, raised to rateLimitMinBackoff when
// the failure was a rate-limited response, since the early backoff steps are
// shorter than the minimum delay the import API mandates for an HTTP 429.
func retryDelay(attempt int, err error) time.Duration {
	d := backoffFor(attempt)
	if errors.Is(err, chronicle.ErrRateLimited) && d < rateLimitMinBackoff {
		return rateLimitMinBackoff
	}
	return d
}
