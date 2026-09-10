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

package dedup

import (
	"sync"
	"testing"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// makeIndicator builds a test indicator mirroring tests/test_icache.py.
func makeIndicator(id, value string, labels, relations []any, lastUpdated string) indicator.Indicator {
	ind := indicator.Indicator{
		"id":           id,
		"indicator":    value,
		"type":         "ip_address",
		"last_updated": lastUpdated,
	}
	if labels != nil {
		ind["labels"] = labels
	}
	if relations != nil {
		ind["relations"] = relations
	}
	return ind
}

func basic() indicator.Indicator {
	return makeIndicator("ind-1", "1.2.3.4", nil, nil, "2024-01-01")
}

func newCache(t *testing.T, maxSize int) *Cache {
	t.Helper()
	c, err := New(maxSize)
	if err != nil {
		t.Fatalf("New(%d): %v", maxSize, err)
	}
	return c
}

func TestUnrecordedNotSeen(t *testing.T) {
	c := newCache(t, 0)
	if c.Seen(basic()) {
		t.Error("unrecorded indicator reported as seen")
	}
}

func TestRecordedIsSeen(t *testing.T) {
	c := newCache(t, 0)
	c.Record(basic())
	if !c.Seen(basic()) {
		t.Error("recorded indicator not reported as seen")
	}
}

func TestSeenDoesNotRecord(t *testing.T) {
	c := newCache(t, 0)
	// A pure lookup must not remember the indicator, so an indicator that is
	// only ever checked (never delivered) is still offered on the next fetch.
	if c.Seen(basic()) {
		t.Error("unrecorded indicator reported as seen")
	}
	if c.Seen(basic()) {
		t.Error("Seen recorded the indicator; a check must not mutate the cache")
	}
	if size := c.Stats().Size; size != 0 {
		t.Errorf("Seen changed cache size to %d, want 0", size)
	}
}

func TestContentChangeNotSeen(t *testing.T) {
	c := newCache(t, 0)
	c.Record(makeIndicator("ind-1", "1.2.3.4", nil, nil, "2024-01-01"))
	if c.Seen(makeIndicator("ind-1", "5.6.7.8", nil, nil, "2024-01-01")) {
		t.Error("changed content reported as seen")
	}
}

func TestLastUpdatedIgnored(t *testing.T) {
	c := newCache(t, 0)
	c.Record(makeIndicator("ind-1", "1.2.3.4", nil, nil, "2024-01-01"))
	if !c.Seen(makeIndicator("ind-1", "1.2.3.4", nil, nil, "2024-06-01")) {
		t.Error("last_updated change should be ignored for dedup")
	}
}

func TestLabelCreatedOnIgnored(t *testing.T) {
	c := newCache(t, 0)
	labels1 := []any{map[string]any{"name": "malware", "created_on": 1700000000.0}}
	labels2 := []any{map[string]any{"name": "malware", "created_on": 1700099999.0}}
	c.Record(makeIndicator("ind-1", "1.2.3.4", labels1, nil, "2024-01-01"))
	if !c.Seen(makeIndicator("ind-1", "1.2.3.4", labels2, nil, "2024-01-01")) {
		t.Error("label created_on change should be ignored for dedup")
	}
}

func TestLabelLastValidOnIgnored(t *testing.T) {
	c := newCache(t, 0)
	labels1 := []any{map[string]any{"name": "malware", "last_valid_on": 1700000000.0}}
	labels2 := []any{map[string]any{"name": "malware", "last_valid_on": 1700099999.0}}
	c.Record(makeIndicator("ind-1", "1.2.3.4", labels1, nil, "2024-01-01"))
	if !c.Seen(makeIndicator("ind-1", "1.2.3.4", labels2, nil, "2024-01-01")) {
		t.Error("label last_valid_on change should be ignored for dedup")
	}
}

func TestRelationCreatedDateIgnored(t *testing.T) {
	c := newCache(t, 0)
	rels1 := []any{map[string]any{"id": "rel-1", "type": "parent", "created_date": 1700000000.0}}
	rels2 := []any{map[string]any{"id": "rel-1", "type": "parent", "created_date": 1700099999.0}}
	c.Record(makeIndicator("ind-1", "1.2.3.4", nil, rels1, "2024-01-01"))
	if !c.Seen(makeIndicator("ind-1", "1.2.3.4", nil, rels2, "2024-01-01")) {
		t.Error("relation created_date change should be ignored for dedup")
	}
}

func TestInputNotMutated(t *testing.T) {
	c := newCache(t, 0)
	labels := []any{map[string]any{"name": "malware", "created_on": 1700000000.0}}
	ind := makeIndicator("ind-1", "1.2.3.4", labels, nil, "2024-01-01")
	c.Record(ind)

	// The forwarded indicator must retain all its fields; dedup only hashes a copy.
	if _, ok := ind["id"]; !ok {
		t.Error("Record removed id from the caller's indicator")
	}
	if _, ok := ind["last_updated"]; !ok {
		t.Error("Record removed last_updated from the caller's indicator")
	}
	labelsSlice, ok := ind["labels"].([]any)
	if !ok || len(labelsSlice) == 0 {
		t.Fatal("labels should be a non-empty slice")
	}
	label, ok := labelsSlice[0].(map[string]any)
	if !ok {
		t.Fatal("label should be an object")
	}
	if _, ok := label["created_on"]; !ok {
		t.Error("Record removed created_on from the caller's label")
	}
}

func TestMissingIDNoPanic(t *testing.T) {
	c := newCache(t, 0)
	ind := indicator.Indicator{"indicator": "1.2.3.4", "type": "ip_address"}
	// Must not panic on a missing id (fixes the latent Python KeyError).
	if c.Seen(ind) {
		t.Error("unrecorded id-less indicator reported as seen")
	}
	c.Record(ind)
	if !c.Seen(ind) {
		t.Error("recorded id-less indicator not reported as seen")
	}
}

func TestCacheStaysAtMaxSize(t *testing.T) {
	c := newCache(t, 3)
	for i := range 5 {
		c.Record(makeIndicator("ind-"+itoa(i), "1.2.3.4", nil, nil, "2024-01-01"))
	}
	stats := c.Stats()
	if stats.Size != 3 {
		t.Errorf("Size = %d, want 3", stats.Size)
	}
	if stats.Evictions != 2 {
		t.Errorf("Evictions = %d, want 2", stats.Evictions)
	}
}

func TestLRURecentlyAccessedSurvives(t *testing.T) {
	c := newCache(t, 3)
	c.Record(makeIndicator("ind-0", "1.2.3.4", nil, nil, "2024-01-01"))
	c.Record(makeIndicator("ind-1", "1.2.3.4", nil, nil, "2024-01-01"))
	c.Record(makeIndicator("ind-2", "1.2.3.4", nil, nil, "2024-01-01"))
	// Re-access ind-0 so it becomes most-recently-used.
	c.Record(makeIndicator("ind-0", "1.2.3.4", nil, nil, "2024-01-01"))
	// Inserting a 4th entry should evict the least-recently-used, ind-1.
	c.Record(makeIndicator("ind-3", "1.2.3.4", nil, nil, "2024-01-01"))

	if !c.lru.Contains("ind-0") {
		t.Error("ind-0 should have survived (recently accessed)")
	}
	if c.lru.Contains("ind-1") {
		t.Error("ind-1 should have been evicted (least recently used)")
	}
	if !c.lru.Contains("ind-2") || !c.lru.Contains("ind-3") {
		t.Error("ind-2 and ind-3 should be present")
	}
}

func TestUnboundedNeverEvicts(t *testing.T) {
	c := newCache(t, 0)
	for i := range 1000 {
		c.Record(makeIndicator("ind-"+itoa(i), "1.2.3.4", nil, nil, "2024-01-01"))
	}
	stats := c.Stats()
	if stats.Size != 1000 {
		t.Errorf("Size = %d, want 1000", stats.Size)
	}
	if stats.Evictions != 0 {
		t.Errorf("Evictions = %d, want 0", stats.Evictions)
	}
}

func TestStatsValues(t *testing.T) {
	c := newCache(t, 5)
	for i := range 7 {
		c.Record(makeIndicator("ind-"+itoa(i), "1.2.3.4", nil, nil, "2024-01-01"))
	}
	got := c.Stats()
	want := Stats{Size: 5, MaxSize: 5, Evictions: 2}
	if got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
}

// TestConcurrentSeenAndRecord drives the cache from multiple goroutines so the
// race detector can prove Seen, Record, and Stats are safe for concurrent use
// by the reader and writer.
func TestConcurrentSeenAndRecord(t *testing.T) {
	c := newCache(t, 1000)
	const workers = 8
	const perWorker = 500

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range perWorker {
				ind := makeIndicator("ind-"+itoa(w)+"-"+itoa(i), "1.2.3.4", nil, nil, "2024-01-01")
				if !c.Seen(ind) {
					c.Record(ind)
				}
				_ = c.Stats()
			}
		}(w)
	}
	wg.Wait()
}

// itoa is a tiny local integer formatter to keep test indicator ids readable
// without importing strconv in every call site.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
