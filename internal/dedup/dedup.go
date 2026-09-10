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

// Package dedup suppresses re-sending indicators whose meaningful content has
// not changed since they were last seen, keyed by indicator id.
//
// Volatile fields that change on every fetch (the pagination marker and the
// per-label/per-relation timestamps) are excluded from the content hash so
// that only substantive changes cause an indicator to be re-sent.
package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// Cache tracks the content hash of each indicator id it has seen. When bounded
// it evicts least-recently-used entries; when max size is non-positive it grows
// without bound. It is safe for concurrent use.
type Cache struct {
	mu        sync.Mutex
	maxSize   int
	lru       *lru.Cache[string, string]
	plain     map[string]string
	evictions int
}

// Stats is a point-in-time snapshot of cache occupancy.
type Stats struct {
	Size      int
	MaxSize   int
	Evictions int
}

// New returns a Cache. A maxSize of zero or less makes the cache unbounded.
func New(maxSize int) (*Cache, error) {
	c := &Cache{maxSize: maxSize}
	if maxSize <= 0 {
		c.plain = make(map[string]string)
		return c, nil
	}
	// The eviction callback runs synchronously inside Add while the caller
	// already holds c.mu, so it must not lock again.
	l, err := lru.NewWithEvict(maxSize, func(string, string) {
		c.evictions++
	})
	if err != nil {
		return nil, err
	}
	c.lru = l
	return c, nil
}

// Seen reports whether ind has already been recorded with identical content.
// It is a pure lookup: it never mutates the cache or ind, so an indicator that
// is checked but never delivered is not remembered. Call Record after the
// indicator has been accepted downstream to remember it.
func (c *Cache) Seen(ind indicator.Indicator) bool {
	id, _ := ind["id"].(string)
	hash := contentHash(ind)

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, ok := c.get(id)
	return ok && prev == hash
}

// Record remembers ind's current content so a later Seen call with identical
// content reports a duplicate. It is called only after the indicator has been
// accepted downstream, so an indicator whose delivery never succeeds is not
// recorded: the resume position is held back to before it, so it is re-fetched
// and re-sent — on the next fetch cycle in-process, or after a restart from the
// last persisted marker — rather than being silently dropped. It never mutates
// ind.
func (c *Cache) Record(ind indicator.Indicator) {
	id, _ := ind["id"].(string)
	hash := contentHash(ind)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.set(id, hash)
}

// Stats returns a snapshot of the cache for logging.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Size: c.size(), MaxSize: c.maxSize, Evictions: c.evictions}
}

func (c *Cache) get(id string) (string, bool) {
	if c.lru != nil {
		return c.lru.Get(id)
	}
	v, ok := c.plain[id]
	return v, ok
}

func (c *Cache) set(id, hash string) {
	if c.lru != nil {
		c.lru.Add(id, hash)
		return
	}
	if c.plain == nil {
		c.plain = make(map[string]string)
	}
	c.plain[id] = hash
}

func (c *Cache) size() int {
	if c.lru != nil {
		return c.lru.Len()
	}
	return len(c.plain)
}

// excludedTop are indicator fields omitted from the content hash because they
// change on every fetch or identify rather than describe the indicator.
var excludedTop = []string{"_marker", "last_updated", "id"}

// contentHash returns the SHA-256 of the indicator's canonical JSON with the
// volatile fields removed. Removal is performed on a deep copy, so the caller's
// indicator is never modified, and missing fields are simply skipped.
func contentHash(ind indicator.Indicator) string {
	cp := deepCopy(ind)
	for _, k := range excludedTop {
		delete(cp, k)
	}
	for _, l := range indicator.Objects(cp["labels"]) {
		delete(l, "created_on")
		delete(l, "last_valid_on")
	}
	for _, r := range indicator.Objects(cp["relations"]) {
		delete(r, "created_date")
		delete(r, "last_valid_date")
	}

	// encoding/json sorts map keys, giving a canonical encoding equivalent to
	// Python's json.dumps(sort_keys=True).
	data, err := json.Marshal(cp)
	if err != nil {
		// Indicators originate from decoded JSON, so all values are
		// marshalable; fall back to the id-only hash if that ever fails.
		data = []byte{}
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// deepCopy clones an indicator via a JSON round trip so that field deletions do
// not touch the original (whose nested maps and slices are shared by reference).
func deepCopy(ind indicator.Indicator) map[string]any {
	raw, err := json.Marshal(ind)
	if err != nil {
		return map[string]any{}
	}
	var cp map[string]any
	if err := json.Unmarshal(raw, &cp); err != nil {
		return map[string]any{}
	}
	return cp
}
