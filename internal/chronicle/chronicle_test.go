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

package chronicle

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// newTestClient builds a Client pointing at srv with a fixed clock, bypassing
// the Google credential exchange that New performs in production.
func newTestClient(srv *httptest.Server) *Client {
	fixed := time.Unix(1_000_000, 0).UTC()
	return &Client{
		customerID: "cust-1",
		endpoint:   srv.URL,
		newClient:  func() *http.Client { return srv.Client() },
		http:       srv.Client(),
		now:        func() time.Time { return fixed },
	}
}

func TestEndpointFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"empty defaults to US", "", "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
		{"unknown defaults to US", "narnia", "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
		{"US explicit", "US", "https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
		{"legacy EU", "EU", "https://europe-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
		{"legacy UK", "UK", "https://europe-west2-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
		{"lower-case is matched", "eu", "https://europe-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
		{"gcp code", "asia-south1", "https://asia-south1-malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := endpointFor(tc.region); got != tc.want {
				t.Errorf("endpointFor(%q) = %q, want %q", tc.region, got, tc.want)
			}
		})
	}
}

func TestSendPostsBatchShape(t *testing.T) {
	var got request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	batch := []indicator.Indicator{
		{"id": "ind-1", "type": "domain", "indicator": "evil.com", "published_date": 1700000000.0},
		{"id": "ind-2", "type": "ip_address", "indicator": "1.2.3.4", "last_updated": 1700000001.0},
	}
	if err := c.Send(context.Background(), batch); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got.CustomerID != "cust-1" {
		t.Errorf("customer_id = %q, want cust-1", got.CustomerID)
	}
	if got.LogType != "CROWDSTRIKE_IOC" {
		t.Errorf("log_type = %q, want CROWDSTRIKE_IOC", got.LogType)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(got.Entries))
	}

	// log_text must be the verbatim indicator JSON.
	var first indicator.Indicator
	if err := json.Unmarshal([]byte(got.Entries[0].LogText), &first); err != nil {
		t.Fatalf("log_text is not valid JSON: %v", err)
	}
	if first["indicator"] != "evil.com" {
		t.Errorf("log_text indicator = %v, want evil.com", first["indicator"])
	}
}

func TestSendTimestampPrecedence(t *testing.T) {
	fixed := time.Unix(1_000_000, 0).UTC()
	tests := []struct {
		name string
		ind  indicator.Indicator
		want int64
	}{
		{
			name: "published_date wins over last_updated",
			ind:  indicator.Indicator{"published_date": 1700000000.0, "last_updated": 1600000000.0},
			want: 1700000000 * 1_000_000,
		},
		{
			name: "last_updated used when no published_date",
			ind:  indicator.Indicator{"last_updated": 1600000000.0},
			want: 1600000000 * 1_000_000,
		},
		{
			name: "zero published_date falls through to last_updated",
			ind:  indicator.Indicator{"published_date": 0.0, "last_updated": 1600000000.0},
			want: 1600000000 * 1_000_000,
		},
		{
			name: "numeric string is parsed",
			ind:  indicator.Indicator{"published_date": "1700000000"},
			want: 1700000000 * 1_000_000,
		},
		{
			name: "no usable field falls back to now",
			ind:  indicator.Indicator{"type": "domain"},
			want: fixed.UnixMicro(),
		},
		{
			name: "unparseable string falls back to now",
			ind:  indicator.Indicator{"published_date": "not-a-number"},
			want: fixed.UnixMicro(),
		},
	}

	c := &Client{now: func() time.Time { return fixed }}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.indicatorTS(tc.ind); got != tc.want {
				t.Errorf("indicatorTS = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSendReturnsErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "backend exploded")
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.Send(context.Background(), []indicator.Indicator{{"id": "ind-1"}})
	if err == nil {
		t.Fatal("Send returned nil error on 500 response")
	}
}

func TestResetSessionRebuildsClient(t *testing.T) {
	rebuilt := &http.Client{}
	c := &Client{
		newClient: func() *http.Client { return rebuilt },
		http:      &http.Client{},
	}
	c.ResetSession()
	if c.http != rebuilt {
		t.Error("ResetSession did not replace the HTTP client")
	}
}
