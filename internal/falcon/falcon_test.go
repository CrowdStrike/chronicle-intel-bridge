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

package falcon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

func strptr(s string) *string { return &s }

// fakeQuerier returns scripted responses in order, recording the filter of each
// call, and optionally fails a fixed number of times before succeeding.
type fakeQuerier struct {
	pages       [][]*models.DomainPublicIndicatorV3
	call        int
	filters     []string
	failFirst   int
	failErr     error
	emptyErrors bool
}

func (f *fakeQuerier) QueryIntelIndicatorEntities(params *intel.QueryIntelIndicatorEntitiesParams, _ ...intel.ClientOption) (*intel.QueryIntelIndicatorEntitiesOK, error) {
	if params.Filter != nil {
		f.filters = append(f.filters, *params.Filter)
	}
	if f.failFirst > 0 {
		f.failFirst--
		if f.failErr != nil {
			return nil, f.failErr
		}
		return nil, errors.New("transient")
	}
	if f.emptyErrors {
		return &intel.QueryIntelIndicatorEntitiesOK{
			Payload: &models.DomainPublicIndicatorsV3Response{
				Errors: []*models.MsaAPIError{{Message: strptr("boom")}},
			},
		}, nil
	}

	var page []*models.DomainPublicIndicatorV3
	if f.call < len(f.pages) {
		page = f.pages[f.call]
	}
	f.call++
	return &intel.QueryIntelIndicatorEntitiesOK{
		Payload: &models.DomainPublicIndicatorsV3Response{Resources: page},
	}, nil
}

// resource builds a typed indicator resource with the given id and _marker.
func resource(id, marker string) *models.DomainPublicIndicatorV3 {
	return &models.DomainPublicIndicatorV3{ID: strptr(id), Marker: strptr(marker)}
}

// fullPage returns a page of exactly pageLimit resources, so Stream treats it as
// a non-terminal page and fetches again.
func fullPage(startMarker string) []*models.DomainPublicIndicatorV3 {
	page := make([]*models.DomainPublicIndicatorV3, pageLimit)
	for i := range pageLimit {
		page[i] = resource("id", startMarker)
	}
	return page
}

func newTestClient(q indicatorQuerier) *Client {
	return &Client{intel: q, retryDelay: time.Millisecond}
}

func TestCursorFilter(t *testing.T) {
	tests := []struct {
		name string
		cur  Cursor
		want string
	}{
		{"marker cursor", FromMarker("MARK-1"), "_marker:>='MARK-1'+deleted:false"},
		{"time cursor", FromTime(1700000000), "last_updated:>=1700000000+deleted:false"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.cur.filter(); got != tc.want {
				t.Errorf("filter() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStreamPassesCursorFilterToAPI(t *testing.T) {
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{{resource("a", "m1")}}}
	c := newTestClient(q)

	err := c.Stream(context.Background(), FromMarker("MARK-1"), func([]indicator.Indicator, string) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(q.filters) != 1 || q.filters[0] != "_marker:>='MARK-1'+deleted:false" {
		t.Errorf("filters = %v, want single marker filter", q.filters)
	}
}

func TestStreamStopsOnShortPage(t *testing.T) {
	// A single page shorter than pageLimit must terminate the stream after one
	// fetch even though its marker is non-empty.
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{
		{resource("a", "m1"), resource("b", "m2")},
	}}
	c := newTestClient(q)

	var pages int
	var lastSeen string
	err := c.Stream(context.Background(), FromTime(1), func(page []indicator.Indicator, marker string) error {
		pages++
		lastSeen = marker
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if pages != 1 {
		t.Errorf("pages = %d, want 1", pages)
	}
	if lastSeen != "m2" {
		t.Errorf("last marker = %q, want m2", lastSeen)
	}
	if q.call != 1 {
		t.Errorf("api calls = %d, want 1", q.call)
	}
}

func TestStreamPaginatesUntilPartialPage(t *testing.T) {
	// First page is full (pageLimit) so Stream fetches again; the second page is
	// short and ends the stream.
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{
		fullPage("m-full"),
		{resource("tail", "m-tail")},
	}}
	c := newTestClient(q)

	var pages, indicators int
	err := c.Stream(context.Background(), FromTime(1), func(page []indicator.Indicator, _ string) error {
		pages++
		indicators += len(page)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if pages != 2 {
		t.Errorf("pages = %d, want 2", pages)
	}
	if indicators != pageLimit+1 {
		t.Errorf("indicators = %d, want %d", indicators, pageLimit+1)
	}
	// The second fetch must resume from the first page's last marker.
	if len(q.filters) != 2 || q.filters[1] != "_marker:>='m-full'+deleted:false" {
		t.Errorf("second filter = %v, want resume from m-full", q.filters)
	}
}

func TestStreamStopsOnEmptyPage(t *testing.T) {
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{{}}}
	c := newTestClient(q)

	var pages int
	err := c.Stream(context.Background(), FromTime(1), func([]indicator.Indicator, string) error {
		pages++
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if pages != 0 {
		t.Errorf("pages = %d, want 0 (empty page yields nothing)", pages)
	}
}

func TestStreamStopsOnEmptyMarker(t *testing.T) {
	// A full page whose last marker is empty must not paginate further, else the
	// next cursor would be a meaningless _marker:>=''.
	page := fullPage("x")
	page[len(page)-1] = resource("last", "")
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{page}}
	c := newTestClient(q)

	var pages int
	err := c.Stream(context.Background(), FromTime(1), func([]indicator.Indicator, string) error {
		pages++
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if pages != 1 {
		t.Errorf("pages = %d, want 1", pages)
	}
	if q.call != 1 {
		t.Errorf("api calls = %d, want 1 (empty marker halts pagination)", q.call)
	}
}

func TestStreamNormalizesResourceFields(t *testing.T) {
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{{resource("ind-42", "m1")}}}
	c := newTestClient(q)

	var got indicator.Indicator
	err := c.Stream(context.Background(), FromTime(1), func(page []indicator.Indicator, _ string) error {
		got = page[0]
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if got["id"] != "ind-42" {
		t.Errorf("normalized id = %v, want ind-42", got["id"])
	}
	if got["_marker"] != "m1" {
		t.Errorf("normalized _marker = %v, want m1", got["_marker"])
	}
}

func TestStreamPropagatesCallbackError(t *testing.T) {
	q := &fakeQuerier{pages: [][]*models.DomainPublicIndicatorV3{fullPage("m1"), fullPage("m2")}}
	c := newTestClient(q)

	sentinel := errors.New("sink closed")
	err := c.Stream(context.Background(), FromTime(1), func([]indicator.Indicator, string) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Stream error = %v, want %v", err, sentinel)
	}
	// The callback failed on the first page, so no second fetch should occur.
	if q.call != 1 {
		t.Errorf("api calls = %d, want 1", q.call)
	}
}

func TestFetchRetriesUntilSuccess(t *testing.T) {
	q := &fakeQuerier{
		pages:     [][]*models.DomainPublicIndicatorV3{{resource("a", "m1")}},
		failFirst: 3,
	}
	c := newTestClient(q)

	var pages int
	err := c.Stream(context.Background(), FromTime(1), func([]indicator.Indicator, string) error {
		pages++
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if pages != 1 {
		t.Errorf("pages = %d, want 1 after transient failures", pages)
	}
}

func TestFetchRetriesOnAPIErrors(t *testing.T) {
	// A 200 response carrying structured errors must be retried, not accepted.
	// With a short retry delay the fetch loops on the error response until the
	// context deadline stops it, proving the callback is never reached.
	q := &fakeQuerier{emptyErrors: true}
	c := newTestClient(q)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := c.Stream(ctx, FromTime(1), func([]indicator.Indicator, string) error {
		t.Error("callback should not run when every response carries API errors")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stream error = %v, want context.DeadlineExceeded", err)
	}
}

func TestFetchStopsOnContextCancel(t *testing.T) {
	q := &fakeQuerier{failFirst: 1 << 30, failErr: errors.New("always down")}
	c := &Client{intel: q, retryDelay: time.Hour} // long delay: only ctx can break it

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.Stream(ctx, FromTime(1), func([]indicator.Indicator, string) error {
		t.Error("callback should not run when the API never succeeds")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stream error = %v, want context.Canceled", err)
	}
}
