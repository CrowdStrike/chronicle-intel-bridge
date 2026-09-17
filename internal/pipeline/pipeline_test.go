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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/chronicle"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/dedup"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/falcon"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// fakeSource replays scripted pages once per cycle. Each page is a slice of
// indicators paired with the marker that follows it. After the scripted pages
// are exhausted it blocks on ctx so the reader idles until cancelled.
type fakeSource struct {
	pages []page
	mu    sync.Mutex
	calls int
}

type page struct {
	indicators []indicator.Indicator
	marker     string
}

func (s *fakeSource) Stream(ctx context.Context, _ falcon.Cursor, fn func([]indicator.Indicator, string) error) error {
	s.mu.Lock()
	first := s.calls == 0
	s.calls++
	s.mu.Unlock()

	if !first {
		<-ctx.Done()
		return ctx.Err()
	}
	for _, p := range s.pages {
		if err := fn(p.indicators, p.marker); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeSource) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// fakeSink records the batches it accepts and can be scripted to fail a fixed
// number of times before succeeding, or to fail forever. When permanent is set
// its failures wrap chronicle.ErrPermanent so the writer must abort without
// retrying. attempts counts every Send call, including failed ones.
type fakeSink struct {
	mu        sync.Mutex
	sent      [][]indicator.Indicator
	failFirst int
	failAll   bool
	permanent bool
	attempts  int
	resets    int
}

func (s *fakeSink) Send(_ context.Context, batch []indicator.Indicator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.permanent {
		return fmt.Errorf("sink rejected batch: %w", chronicle.ErrPermanent)
	}
	if s.failAll {
		return errors.New("sink permanently down")
	}
	if s.failFirst > 0 {
		s.failFirst--
		return errors.New("transient")
	}
	cp := make([]indicator.Indicator, len(batch))
	copy(cp, batch)
	s.sent = append(s.sent, cp)
	return nil
}

func (s *fakeSink) ResetSession() {
	s.mu.Lock()
	s.resets++
	s.mu.Unlock()
}

func (s *fakeSink) sentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *fakeSink) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func (s *fakeSink) resetCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}

// fakeStore records the markers persisted by the writer.
type fakeStore struct {
	mu      sync.Mutex
	markers []string
	err     error
}

func (s *fakeStore) Save(marker string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.markers = append(s.markers, marker)
	return nil
}

func (s *fakeStore) saved() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.markers...)
}

func ind(id string) indicator.Indicator {
	return indicator.Indicator{"id": id, "indicator": id + ".example.com"}
}

func newCache(t *testing.T) *dedup.Cache {
	t.Helper()
	c, err := dedup.New(0)
	if err != nil {
		t.Fatalf("dedup.New: %v", err)
	}
	return c
}

func TestReaderTransformsAndForwards(t *testing.T) {
	src := &fakeSource{pages: []page{
		{indicators: []indicator.Indicator{
			{"id": "a", "_marker": "m1", "labels": []any{map[string]any{"name": "x", "last_valid_on": 1.0}}},
		}, marker: "m1"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: falcon.FromTime(1)})

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Batch, QueueSize)
	go func() { _ = r.Run(ctx, out) }()

	batch := <-out
	cancel()

	if len(batch.Indicators) != 1 {
		t.Fatalf("forwarded %d indicators, want 1", len(batch.Indicators))
	}
	if batch.Marker != "m1" {
		t.Errorf("batch marker = %q, want m1", batch.Marker)
	}
	if _, ok := batch.Indicators[0]["_marker"]; ok {
		t.Error("transform should have removed _marker before forwarding")
	}
}

func TestReaderFiltersAlreadyRecorded(t *testing.T) {
	cache := newCache(t)
	// Simulate an indicator delivered on a previous run: the writer would have
	// recorded it, so the reader must filter it as a duplicate this cycle.
	cache.Record(ind("a"))

	src := &fakeSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a"), ind("b")}, marker: "m1"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: cache, Frequency: time.Hour, Start: falcon.FromTime(1)})

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Batch, QueueSize)
	go func() { _ = r.Run(ctx, out) }()

	batch := <-out
	cancel()

	if len(batch.Indicators) != 1 {
		t.Fatalf("forwarded %d indicators, want 1 (a already recorded)", len(batch.Indicators))
	}
	if id, _ := batch.Indicators[0]["id"].(string); id != "b" {
		t.Errorf("forwarded id = %q, want b", id)
	}
}

func TestReaderClosesChannelOnCancel(t *testing.T) {
	src := &fakeSource{pages: []page{{indicators: []indicator.Indicator{ind("a")}, marker: "m1"}}}
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: falcon.FromTime(1)})

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Batch, QueueSize)
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, out) }()

	<-out // first batch
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// out is closed once Run returns, but the cycle's flush sentinel may still be
	// buffered ahead of the close; drain until the channel is exhausted.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-out:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel not closed after Run returns")
		}
	}
}

func TestWriterChunksLargeBatch(t *testing.T) {
	sink := &fakeSink{}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})

	indicators := make([]indicator.Indicator, chunkSize+1)
	for i := range indicators {
		indicators[i] = ind(string(rune('a' + i%26)))
	}

	in := make(chan Batch, 1)
	in <- Batch{Indicators: indicators, Marker: "m1"}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if sink.sentCount() != 2 {
		t.Errorf("sends = %d, want 2 (chunk of %d + 1)", sink.sentCount(), chunkSize)
	}
	if got := store.saved(); len(got) != 1 || got[0] != "m1" {
		t.Errorf("saved markers = %v, want [m1]", got)
	}
}

// TestWriterSplitsBatchByEncodedSize now lives in internal/chronicle: the sink
// owns the byte-budget split, so the writer only bounds a chunk by count.

func TestWriterSavesMarkerOnlyAfterFullDelivery(t *testing.T) {
	sink := &fakeSink{failAll: true}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})

	// A cancelled context makes the retry loop give up immediately after the
	// first failed attempt, so the permanent failure is reached without waiting
	// out the full backoff schedule.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	close(in)
	if err := w.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := store.saved(); len(got) != 0 {
		t.Errorf("saved markers = %v, want none on permanent failure", got)
	}
}

// TestWriterDropsAndAdvancesOnPermanentRejection verifies the poison-pill fix:
// a chunk the sink rejects as permanent is not retried and does not freeze the
// cycle. It is recorded for dedup and the marker advances past it, so a single
// unacceptable indicator cannot wedge the pipeline behind it. The context is
// left live so success depends on the permanent short-circuit, not on
// cancellation breaking the retry loop.
func TestWriterDropsAndAdvancesOnPermanentRejection(t *testing.T) {
	sink := &fakeSink{permanent: true}
	store := &fakeStore{}
	cache := newCache(t)
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := sink.attemptCount(); got != 1 {
		t.Errorf("send attempts = %d, want 1 (permanent rejection must not retry)", got)
	}
	if w.failed {
		t.Error("cycle marked failed on a permanent rejection; the marker must advance instead of freezing")
	}
	if got := store.saved(); len(got) != 1 || got[0] != "m1" {
		t.Errorf("saved markers = %v, want [m1] advanced past the rejected window", got)
	}
	if !cache.Seen(ind("a")) {
		t.Error("rejected indicator not recorded, so a re-fetch of an earlier window would re-send it")
	}
}

// TestWriterAdvancesPastPoisonChunkToLaterData is the poison-pill regression
// test: a batch whose chunk is permanently rejected must commit its marker and
// let a following batch commit too, proving the resume position advances past a
// permanently unacceptable indicator rather than re-fetching it forever. The
// rejected indicator is recorded so an earlier-window re-fetch suppresses it.
func TestWriterAdvancesPastPoisonChunkToLaterData(t *testing.T) {
	sink := &fakeSink{permanent: true}
	store := &fakeStore{}
	cache := newCache(t)
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	// The poison batch is rejected permanently, yet its marker still advances.
	w.deliver(context.Background(), Batch{Indicators: []indicator.Indicator{ind("poison")}, Marker: "m1"})
	if w.failed {
		t.Fatal("cycle frozen by a permanent rejection; the poison pill would still block the pipeline")
	}
	if w.committed != "m1" {
		t.Errorf("committed = %q, want m1 advanced past the poison chunk", w.committed)
	}

	// Good data delivered afterward commits normally, unblocked by the poison.
	sink.mu.Lock()
	sink.permanent = false
	sink.mu.Unlock()
	w.deliver(context.Background(), Batch{Indicators: []indicator.Indicator{ind("good")}, Marker: "m2"})

	if w.committed != "m2" {
		t.Errorf("committed = %q, want m2: newer data must flow past the poison", w.committed)
	}
	if got := store.saved(); len(got) != 2 || got[0] != "m1" || got[1] != "m2" {
		t.Errorf("saved markers = %v, want [m1 m2]", got)
	}
	if !cache.Seen(ind("poison")) {
		t.Error("poison indicator not recorded, so an earlier-window re-fetch would re-send it")
	}
	if !cache.Seen(ind("good")) {
		t.Error("good indicator delivered but not recorded")
	}
}

func TestWriterRetriesThenSucceeds(t *testing.T) {
	sink := &fakeSink{failFirst: 2}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})
	w.backoff = func(int, error) time.Duration { return 0 }

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if sink.sentCount() != 1 {
		t.Errorf("successful sends = %d, want 1", sink.sentCount())
	}
	if got := store.saved(); len(got) != 1 || got[0] != "m1" {
		t.Errorf("saved markers = %v, want [m1] after transient failures", got)
	}
}

// TestWriterResetsSessionThenSucceeds verifies the writer rebuilds the sink
// session at sessionResetAttempt and then delivers once the transient failures
// clear. Injecting a zero backoff exercises the multi-attempt path without real
// waits.
func TestWriterResetsSessionThenSucceeds(t *testing.T) {
	// Fail every attempt through sessionResetAttempt, then succeed: the reset
	// fires on the failing attempt at that index and the next attempt lands.
	sink := &fakeSink{failFirst: sessionResetAttempt + 1}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})
	w.backoff = func(int, error) time.Duration { return 0 }

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := sink.resetCount(); got != 1 {
		t.Errorf("session resets = %d, want 1 at sessionResetAttempt", got)
	}
	if sink.sentCount() != 1 {
		t.Errorf("successful sends = %d, want 1 after the reset", sink.sentCount())
	}
	if got := store.saved(); len(got) != 1 || got[0] != "m1" {
		t.Errorf("saved markers = %v, want [m1]", got)
	}
}

// TestWriterFreezesWhenRetriesExhausted verifies that a genuinely transient
// failure which never clears is retried the full maxSendAttempts times and then
// freezes the cycle: the marker is held and the cycle is flagged failed so the
// window is re-fetched. Injecting a zero backoff runs the full schedule without
// waits, and the context stays live so the freeze comes from exhaustion, not
// cancellation.
func TestWriterFreezesWhenRetriesExhausted(t *testing.T) {
	sink := &fakeSink{failAll: true}
	store := &fakeStore{}
	cache := newCache(t)
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})
	w.backoff = func(int, error) time.Duration { return 0 }

	w.deliver(context.Background(), Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"})

	if !w.failed {
		t.Error("cycle not flagged failed after exhausting all retries")
	}
	if got := sink.attemptCount(); got != maxSendAttempts {
		t.Errorf("send attempts = %d, want %d (full retry schedule)", got, maxSendAttempts)
	}
	if got := store.saved(); len(got) != 0 {
		t.Errorf("saved markers = %v, want none: an undelivered chunk must freeze the marker", got)
	}
	if cache.Seen(ind("a")) {
		t.Error("undelivered indicator recorded; it would be dropped on re-fetch")
	}
}

func TestWriterDrainsRemainingBatchesAfterClose(t *testing.T) {
	sink := &fakeSink{}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})

	in := make(chan Batch, 3)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	in <- Batch{Indicators: []indicator.Indicator{ind("b")}, Marker: "m2"}
	in <- Batch{Indicators: []indicator.Indicator{ind("c")}, Marker: "m3"}
	close(in)

	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.saved(); len(got) != 3 {
		t.Errorf("saved markers = %v, want all three drained", got)
	}
}

func TestWriterSkipsMarkerSaveWhenEmpty(t *testing.T) {
	sink := &fakeSink{}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: ""}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if sink.sentCount() != 1 {
		t.Errorf("sends = %d, want 1", sink.sentCount())
	}
	if got := store.saved(); len(got) != 0 {
		t.Errorf("saved markers = %v, want none for empty marker", got)
	}
}

func TestWriterRecordsDeliveredIndicators(t *testing.T) {
	sink := &fakeSink{}
	store := &fakeStore{}
	cache := newCache(t)
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !cache.Seen(ind("a")) {
		t.Error("a delivered indicator was not recorded, so it would be re-sent needlessly")
	}
}

// TestWriterDoesNotRecordFailedIndicators guards the correctness fix: an
// indicator whose delivery never succeeds must not be recorded, or a later
// fetch would treat it as a duplicate and drop it before it is ever delivered.
func TestWriterDoesNotRecordFailedIndicators(t *testing.T) {
	sink := &fakeSink{failAll: true}
	store := &fakeStore{}
	cache := newCache(t)
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	// A cancelled context makes the retry loop give up immediately, reaching the
	// permanent-failure path without waiting out the full backoff schedule.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	in := make(chan Batch, 1)
	in <- Batch{Indicators: []indicator.Indicator{ind("a")}, Marker: "m1"}
	close(in)
	if err := w.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if cache.Seen(ind("a")) {
		t.Error("indicator recorded despite delivery never succeeding; it would be dropped on re-fetch")
	}
}

func TestBackoffForCaps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{5, 32 * time.Second},
		{6, maxBackoff},
		{29, maxBackoff},
	}
	for _, tc := range tests {
		if got := backoffFor(tc.attempt); got != tc.want {
			t.Errorf("backoffFor(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

// TestRetryDelayRateLimitFloor verifies the retry wait is raised to the
// rate-limit minimum only for a rate-limited error and only while the plain
// exponential backoff is below that floor; other errors and later attempts keep
// the exponential value.
func TestRetryDelayRateLimitFloor(t *testing.T) {
	t.Parallel()
	rateLimited := fmt.Errorf("chronicle rejected: %w", chronicle.ErrRateLimited)
	transient := errors.New("transient network error")
	tests := []struct {
		name    string
		attempt int
		err     error
		want    time.Duration
	}{
		{"rate limit floors attempt 0", 0, rateLimited, rateLimitMinBackoff},
		{"rate limit floors attempt 4 (16s < 30s)", 4, rateLimited, rateLimitMinBackoff},
		{"rate limit keeps larger backoff at attempt 5", 5, rateLimited, 32 * time.Second},
		{"non-rate-limit error uses plain backoff", 0, transient, 1 * time.Second},
		{"non-rate-limit error at attempt 4", 4, transient, 16 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := retryDelay(tc.attempt, tc.err); got != tc.want {
				t.Errorf("retryDelay(%d, %v) = %v, want %v", tc.attempt, tc.err, got, tc.want)
			}
		})
	}
}

// recordingSource serves the same scripted pages on every Stream call and
// records the cursor it was invoked with, so a test can assert where the next
// cycle would resume.
type recordingSource struct {
	pages   []page
	mu      sync.Mutex
	cursors []falcon.Cursor
}

func (s *recordingSource) Stream(_ context.Context, cur falcon.Cursor, fn func([]indicator.Indicator, string) error) error {
	s.mu.Lock()
	s.cursors = append(s.cursors, cur)
	s.mu.Unlock()
	for _, p := range s.pages {
		if err := fn(p.indicators, p.marker); err != nil {
			return err
		}
	}
	return nil
}

// fakeWriter drains out in place of the real writer, replying to each flush
// sentinel with the next scripted report. It lets reader tests exercise the
// next-cursor decision without running real delivery and its backoff schedule.
type fakeWriter struct {
	reports []deliveryReport
	mu      sync.Mutex
	data    []Batch
	idx     int
}

func (f *fakeWriter) run(out <-chan Batch) {
	for b := range out {
		if b.flush != nil {
			f.mu.Lock()
			rep := f.reports[f.idx]
			f.idx++
			f.mu.Unlock()
			b.flush <- rep
			continue
		}
		f.mu.Lock()
		f.data = append(f.data, b)
		f.mu.Unlock()
	}
}

func (f *fakeWriter) dataBatches() []Batch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Batch(nil), f.data...)
}

// TestWriterHoldsCommittedMarkerOnFailure verifies the writer freezes its
// committed marker and flags the cycle failed when a batch cannot be delivered,
// so the resume position is not advanced past undelivered data.
func TestWriterHoldsCommittedMarkerOnFailure(t *testing.T) {
	sink := &fakeSink{failAll: true}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: newCache(t)})
	w.committed = "m2" // a prior batch delivered cleanly

	// A cancelled context makes the retry loop give up immediately, reaching the
	// permanent-failure path without waiting out the full backoff schedule.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w.deliver(ctx, Batch{Indicators: []indicator.Indicator{ind("c")}, Marker: "m3"})

	if !w.failed {
		t.Error("cycle not marked failed after a permanent delivery failure")
	}
	if w.committed != "m2" {
		t.Errorf("committed = %q, want m2 held back on failure", w.committed)
	}
	if got := store.saved(); len(got) != 0 {
		t.Errorf("saved markers = %v, want none on failure", got)
	}
}

// TestWriterDoesNotAdvanceMarkerAfterEarlierFailure guards the FIFO ordering
// trap: once a batch has failed this cycle, a later batch that succeeds must not
// advance the committed marker past the failed one, or the failed data would be
// buried for both in-process and restart recovery.
func TestWriterDoesNotAdvanceMarkerAfterEarlierFailure(t *testing.T) {
	sink := &fakeSink{}
	store := &fakeStore{}
	cache := newCache(t)
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	// B2 delivers cleanly and commits its marker.
	w.deliver(context.Background(), Batch{Indicators: []indicator.Indicator{ind("b2")}, Marker: "m2"})
	if w.committed != "m2" {
		t.Fatalf("committed = %q after clean delivery, want m2", w.committed)
	}

	// B3 fails permanently, freezing the cycle.
	failCtx, cancel := context.WithCancel(context.Background())
	cancel()
	sink.mu.Lock()
	sink.failAll = true
	sink.mu.Unlock()
	w.deliver(failCtx, Batch{Indicators: []indicator.Indicator{ind("b3")}, Marker: "m3"})

	// B4 succeeds afterward, but must not bury B3 by advancing the marker.
	sink.mu.Lock()
	sink.failAll = false
	sink.mu.Unlock()
	w.deliver(context.Background(), Batch{Indicators: []indicator.Indicator{ind("b4")}, Marker: "m4"})

	if w.committed != "m2" {
		t.Errorf("committed = %q, want m2 frozen at the last batch before the failure", w.committed)
	}
	if got := store.saved(); len(got) != 1 || got[0] != "m2" {
		t.Errorf("saved markers = %v, want [m2] only", got)
	}
	if !cache.Seen(ind("b4")) {
		t.Error("b4 was delivered but not recorded, so it would be needlessly re-sent")
	}
	if cache.Seen(ind("b3")) {
		t.Error("b3 was never delivered but is recorded, so it would be dropped on re-fetch")
	}
}

// TestWriterReportsStateAndResetsFailedOnFlush verifies the flush sentinel is
// answered with the current committed marker and failure flag, and that the
// per-cycle failure flag is cleared once the sentinel is answered.
func TestWriterReportsStateAndResetsFailedOnFlush(t *testing.T) {
	w := NewWriter(WriterConfig{Sink: &fakeSink{}, State: &fakeStore{}, Dedup: newCache(t)})
	w.committed = "m5"
	w.failed = true

	reply := make(chan deliveryReport, 1)
	in := make(chan Batch, 1)
	in <- Batch{flush: reply}
	close(in)
	if err := w.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	report := <-reply
	if report.committed != "m5" || !report.failed {
		t.Errorf("report = %+v, want {committed:m5 failed:true}", report)
	}
	if w.failed {
		t.Error("failed flag not reset after answering the flush sentinel")
	}
}

// TestReaderAdvancesToLastMarkerOnCleanCycle covers the happy path: with no
// delivery failure the reader advances to the last marker it saw.
func TestReaderAdvancesToLastMarkerOnCleanCycle(t *testing.T) {
	src := &recordingSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m1"},
		{indicators: []indicator.Indicator{ind("b")}, marker: "m2"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: falcon.FromTime(100)})

	out := make(chan Batch, QueueSize)
	fw := &fakeWriter{reports: []deliveryReport{{committed: "m2", failed: false}}}
	go fw.run(out)

	if _, err := r.cycle(context.Background(), out); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	close(out)

	if r.cursor != falcon.FromMarker("m2") {
		t.Errorf("cursor = %+v, want FromMarker(m2) after a clean cycle", r.cursor)
	}
	if got := len(fw.dataBatches()); got != 2 {
		t.Errorf("writer received %d data batches, want 2", got)
	}
}

// TestReaderHoldsCursorAtCommittedMarkerOnFailure covers the hold-back: when a
// delivery fails partway, the reader resumes from the last delivered marker so
// the undelivered window is re-fetched next cycle.
func TestReaderHoldsCursorAtCommittedMarkerOnFailure(t *testing.T) {
	src := &recordingSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m1"},
		{indicators: []indicator.Indicator{ind("b")}, marker: "m2"},
		{indicators: []indicator.Indicator{ind("c")}, marker: "m3"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: falcon.FromTime(100)})

	out := make(chan Batch, QueueSize)
	// The writer delivered through m2, then failed on m3.
	fw := &fakeWriter{reports: []deliveryReport{{committed: "m2", failed: true}}}
	go fw.run(out)

	if _, err := r.cycle(context.Background(), out); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	close(out)

	if r.cursor != falcon.FromMarker("m2") {
		t.Errorf("cursor = %+v, want FromMarker(m2) held back on failure", r.cursor)
	}
}

// TestReaderKeepsCursorWhenColdStartCycleFullyFails covers the cold-start
// all-fail case: with nothing delivered and no prior marker, the reader keeps
// its current cursor so the same window is re-fetched rather than skipped.
func TestReaderKeepsCursorWhenColdStartCycleFullyFails(t *testing.T) {
	start := falcon.FromTime(100)
	src := &recordingSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m1"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: start})

	out := make(chan Batch, QueueSize)
	fw := &fakeWriter{reports: []deliveryReport{{committed: "", failed: true}}}
	go fw.run(out)

	if _, err := r.cycle(context.Background(), out); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	close(out)

	if r.cursor != start {
		t.Errorf("cursor = %+v, want unchanged start cursor %+v on cold-start all-fail", r.cursor, start)
	}
}

// TestReaderAdvancesTimeCursorOnIdleCycle covers a quiet source: a cycle that
// yields no marker and no failure moves the time-based lookback window forward.
func TestReaderAdvancesTimeCursorOnIdleCycle(t *testing.T) {
	src := &recordingSource{pages: nil} // source yields no pages
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: falcon.FromTime(100)})

	out := make(chan Batch, QueueSize)
	fw := &fakeWriter{reports: []deliveryReport{{committed: "", failed: false}}}
	go fw.run(out)

	before := time.Now().Unix()
	if _, err := r.cycle(context.Background(), out); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	after := time.Now().Unix()
	close(out)

	matched := false
	for ts := before; ts <= after; ts++ {
		if r.cursor == falcon.FromTime(ts) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("cursor = %+v, want a time cursor in [%d,%d] on an idle cycle", r.cursor, before, after)
	}
}

// TestReaderAdvancesMarkerWhenAllPagesDeduplicated covers the frontier: a page
// whose indicators are all already delivered forwards no batch, yet its marker
// still advances the cursor because that data is known-delivered.
func TestReaderAdvancesMarkerWhenAllPagesDeduplicated(t *testing.T) {
	cache := newCache(t)
	cache.Record(ind("a")) // already delivered on a previous run

	src := &recordingSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m9"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: cache, Frequency: time.Hour, Start: falcon.FromTime(100)})

	out := make(chan Batch, QueueSize)
	fw := &fakeWriter{reports: []deliveryReport{{committed: "", failed: false}}}
	go fw.run(out)

	if _, err := r.cycle(context.Background(), out); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	close(out)

	if r.cursor != falcon.FromMarker("m9") {
		t.Errorf("cursor = %+v, want FromMarker(m9): a fully deduplicated page still advances the marker", r.cursor)
	}
	if got := len(fw.dataBatches()); got != 0 {
		t.Errorf("writer received %d data batches, want 0 (all deduplicated)", got)
	}
}

// TestReaderCycleReturnsErrorWhenCancelledMidFlush covers graceful shutdown: if
// the context is cancelled while the reader is awaiting the writer's report, the
// cycle returns the cancellation error and does not block or leak a goroutine.
func TestReaderCycleReturnsErrorWhenCancelledMidFlush(t *testing.T) {
	src := &recordingSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m1"},
	}}
	r := NewReader(ReaderConfig{Source: src, Cache: newCache(t), Frequency: time.Hour, Start: falcon.FromTime(100)})

	// No consumer drains out: the data batch and the flush sentinel sit in the
	// buffer, and cycle blocks awaiting the report until the context is cancelled.
	out := make(chan Batch, QueueSize)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	if _, err := r.cycle(ctx, out); !errors.Is(err, context.Canceled) {
		t.Errorf("cycle returned %v, want context.Canceled on shutdown mid-flush", err)
	}
}

// TestPipelineAdvancesCursorAndMarkerEndToEnd wires the real reader and writer
// through the shared channel to confirm the flush handshake advances both the
// in-memory cursor and the persisted marker on a clean cycle.
func TestPipelineAdvancesCursorAndMarkerEndToEnd(t *testing.T) {
	src := &recordingSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m1"},
		{indicators: []indicator.Indicator{ind("b")}, marker: "m2"},
	}}
	cache := newCache(t)
	r := NewReader(ReaderConfig{Source: src, Cache: cache, Frequency: time.Hour, Start: falcon.FromTime(100)})

	sink := &fakeSink{}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	out := make(chan Batch, QueueSize)
	done := make(chan error, 1)
	go func() { done <- w.Run(context.Background(), out) }()

	if _, err := r.cycle(context.Background(), out); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	close(out)
	if err := <-done; err != nil {
		t.Fatalf("writer Run: %v", err)
	}

	if r.cursor != falcon.FromMarker("m2") {
		t.Errorf("cursor = %+v, want FromMarker(m2)", r.cursor)
	}
	if got := store.saved(); len(got) != 2 || got[0] != "m1" || got[1] != "m2" {
		t.Errorf("saved markers = %v, want [m1 m2]", got)
	}
}

// TestReaderRunLogsCycleStatsAndSleeps drives Reader.Run through a full clean
// cycle so the post-cycle stats logging and the frequency sleep both execute,
// then lets the source block on the next cycle until shutdown. The existing Run
// tests all cancel mid-flush, so cycle returns a context error and Run exits
// before reaching those paths; this one takes the loop's non-error branch.
func TestReaderRunLogsCycleStatsAndSleeps(t *testing.T) {
	src := &fakeSource{pages: []page{
		{indicators: []indicator.Indicator{ind("a")}, marker: "m1"},
	}}
	cache := newCache(t)
	r := NewReader(ReaderConfig{Source: src, Cache: cache, Frequency: time.Millisecond, Start: falcon.FromTime(1)})

	sink := &fakeSink{}
	store := &fakeStore{}
	w := NewWriter(WriterConfig{Sink: sink, State: store, Dedup: cache})

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Batch, QueueSize)
	wdone := make(chan error, 1)
	go func() { wdone <- w.Run(context.Background(), out) }()
	rdone := make(chan error, 1)
	go func() { rdone <- r.Run(ctx, out) }()

	// The first cycle delivers cleanly, logs its stats, and sleeps; the reader
	// then enters a second cycle whose source call blocks until shutdown. Waiting
	// for that second call proves the post-cycle logging and frequency-sleep paths
	// ran before we cancel.
	waitFor(t, func() bool { return src.callCount() >= 2 })
	cancel()

	if err := <-rdone; err != nil {
		t.Fatalf("reader Run returned %v, want nil on cancel", err)
	}
	if err := <-wdone; err != nil {
		t.Fatalf("writer Run returned %v", err)
	}
	if got := store.saved(); len(got) != 1 || got[0] != "m1" {
		t.Errorf("saved markers = %v, want [m1]", got)
	}
}

// TestWriterRunReturnsOnCancelDuringFlushReply confirms the writer exits cleanly
// when the context is cancelled while it is trying to answer a flush sentinel
// whose reply channel no reader is draining, so it cannot leak the goroutine.
func TestWriterRunReturnsOnCancelDuringFlushReply(t *testing.T) {
	w := NewWriter(WriterConfig{Sink: &fakeSink{}, State: &fakeStore{}, Dedup: newCache(t)})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Unbuffered reply with no receiver: the sentinel reply cannot be sent, so the
	// already-cancelled context is the only ready case in Run's select.
	in := make(chan Batch, 1)
	in <- Batch{flush: make(chan deliveryReport)}
	close(in)

	if err := w.Run(ctx, in); err != nil {
		t.Fatalf("Run returned %v, want nil when cancelled mid-flush reply", err)
	}
}

// waitFor blocks until cond returns true, failing the test if it does not within
// a short deadline. It polls so a test can wait on state a background goroutine
// advances without a bespoke synchronization channel.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("condition not met within deadline")
		case <-time.After(time.Millisecond):
		}
	}
}
