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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// testInstancePath is the instance path used by the test clients; it mirrors the
// projects/{project}/locations/{region}/instances/{instance} layout New builds.
const testInstancePath = "projects/proj-1/locations/us/instances/cust-1"

// newTestClient builds a Client pointing at srv with a fixed clock, bypassing
// the Google credential exchange that New performs in production.
func newTestClient(srv *httptest.Server) *Client {
	fixed := time.Unix(1_000_000, 0).UTC()
	return &Client{
		baseURL:      srv.URL,
		instancePath: testInstancePath,
		newClient:    func() *http.Client { return srv.Client() },
		http:         srv.Client(),
		now:          func() time.Time { return fixed },
	}
}

func TestCanonicalRegion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		region string
		want   string
		ok     bool
	}{
		{"empty defaults to US", "", "us", true},
		{"US explicit", "US", "us", true},
		{"us lower-case", "us", "us", true},
		{"legacy EU", "EU", "europe", true},
		{"legacy UK", "UK", "europe-west2", true},
		{"legacy IL", "IL", "me-west1", true},
		{"eu multi-region distinct from legacy EU", "eu", "eu", true},
		{"gcp region", "asia-south1", "asia-south1", true},
		{"newly added gcp region", "europe-central2", "europe-central2", true},
		{"underscores become hyphens", "asia_south1", "asia-south1", true},
		{"surrounding space trimmed", " europe-west2 ", "europe-west2", true},
		{"unknown region", "narnia", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := canonicalRegion(tc.region)
			if ok != tc.ok || got != tc.want {
				t.Errorf("canonicalRegion(%q) = (%q, %t), want (%q, %t)", tc.region, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestValidateRegion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		region  string
		wantErr bool
	}{
		{"empty is valid", "", false},
		{"legacy alias", "EU", false},
		{"gcp region", "australia-southeast1", false},
		{"unknown region", "narnia", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateRegion(tc.region)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRegion(%q) error = %v, wantErr %t", tc.region, err, tc.wantErr)
			}
		})
	}
}

func TestImportURL(t *testing.T) {
	t.Parallel()
	c := &Client{baseURL: "https://us-chronicle.googleapis.com", instancePath: testInstancePath}
	want := "https://us-chronicle.googleapis.com/v1/" + testInstancePath + "/logTypes/CROWDSTRIKE_IOC/logs:import"
	if got := c.importURL(); got != want {
		t.Errorf("importURL() = %q, want %q", got, want)
	}
}

func TestSendPostsImportShape(t *testing.T) {
	var got importRequest
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
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

	wantPath := "/v1/" + testInstancePath + "/logTypes/CROWDSTRIKE_IOC/logs:import"
	if gotPath != wantPath {
		t.Errorf("request path = %q, want %q", gotPath, wantPath)
	}
	if len(got.InlineSource.Logs) != 2 {
		t.Fatalf("logs = %d, want 2", len(got.InlineSource.Logs))
	}

	// data must be the base64-encoded, verbatim indicator JSON.
	raw, err := base64.StdEncoding.DecodeString(got.InlineSource.Logs[0].Data)
	if err != nil {
		t.Fatalf("data is not valid base64: %v", err)
	}
	var first indicator.Indicator
	if err := json.Unmarshal(raw, &first); err != nil {
		t.Fatalf("decoded data is not valid JSON: %v", err)
	}
	if first["indicator"] != "evil.com" {
		t.Errorf("decoded indicator = %v, want evil.com", first["indicator"])
	}

	// timestamps must be RFC 3339 and collection must be strictly after the event.
	entry := got.InlineSource.Logs[0]
	eventTime, err := time.Parse(time.RFC3339, entry.LogEntryTime)
	if err != nil {
		t.Fatalf("log_entry_time %q is not RFC3339: %v", entry.LogEntryTime, err)
	}
	collectionTime, err := time.Parse(time.RFC3339, entry.CollectionTime)
	if err != nil {
		t.Fatalf("collection_time %q is not RFC3339: %v", entry.CollectionTime, err)
	}
	if !collectionTime.After(eventTime) {
		t.Errorf("collection_time %s is not strictly after log_entry_time %s", collectionTime, eventTime)
	}
	if want := time.Unix(1700000000, 0).UTC(); !eventTime.Equal(want) {
		t.Errorf("log_entry_time = %s, want %s", eventTime, want)
	}
}

// TestSendSplitsOversizedBatchByEncodedSize verifies Send splits a batch into
// several import requests when the base64-encoded entries would exceed the
// per-request size budget: three indicators each large enough that any two
// exceed maxImportBytes once encoded must post as three separate requests, and
// every entry must still be delivered exactly once.
func TestSendSplitsOversizedBatchByEncodedSize(t *testing.T) {
	var requests, totalLogs atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req importRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode body: %v", err)
		}
		requests.Add(1)
		totalLogs.Add(int64(len(req.InlineSource.Logs)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	big := strings.Repeat("a", 800*1024) // ~1.04 MiB once base64-encoded
	batch := []indicator.Indicator{
		{"id": "a", "payload": big},
		{"id": "b", "payload": big},
		{"id": "c", "payload": big},
	}
	if err := c.Send(context.Background(), batch); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("import requests = %d, want 3 (each oversized entry in its own request)", got)
	}
	if got := totalLogs.Load(); got != 3 {
		t.Errorf("delivered logs = %d, want 3 (every entry sent exactly once)", got)
	}
}

func TestSendCollectionTimeStrictlyAfterEvent(t *testing.T) {
	// An event dated in the future relative to the clock must still carry a
	// collection_time strictly after the event time, never equal to it.
	var got importRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv) // clock fixed at Unix 1_000_000
	future := float64(2_000_000)
	if err := c.Send(context.Background(), []indicator.Indicator{{"published_date": future}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	entry := got.InlineSource.Logs[0]
	eventTime, err := time.Parse(time.RFC3339, entry.LogEntryTime)
	if err != nil {
		t.Fatalf("log_entry_time %q is not RFC3339: %v", entry.LogEntryTime, err)
	}
	collectionTime, err := time.Parse(time.RFC3339, entry.CollectionTime)
	if err != nil {
		t.Fatalf("collection_time %q is not RFC3339: %v", entry.CollectionTime, err)
	}
	if !collectionTime.After(eventTime) {
		t.Errorf("collection_time %q is not strictly after log_entry_time %q for a future event", entry.CollectionTime, entry.LogEntryTime)
	}
}

// TestSendCollectionTimeStrictlyAfterEventNoTimestamp covers the common path: an
// indicator carrying no usable timestamp falls back to the batch clock for its
// event time, and collection_time must still be nudged strictly past it rather
// than left equal.
func TestSendCollectionTimeStrictlyAfterEventNoTimestamp(t *testing.T) {
	var got importRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.Send(context.Background(), []indicator.Indicator{{"type": "domain"}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	entry := got.InlineSource.Logs[0]
	eventTime, err := time.Parse(time.RFC3339, entry.LogEntryTime)
	if err != nil {
		t.Fatalf("log_entry_time %q is not RFC3339: %v", entry.LogEntryTime, err)
	}
	collectionTime, err := time.Parse(time.RFC3339, entry.CollectionTime)
	if err != nil {
		t.Fatalf("collection_time %q is not RFC3339: %v", entry.CollectionTime, err)
	}
	if !collectionTime.After(eventTime) {
		t.Errorf("collection_time %q is not strictly after log_entry_time %q on the no-timestamp path", entry.CollectionTime, entry.LogEntryTime)
	}
}

func TestIndicatorTimePrecedence(t *testing.T) {
	t.Parallel()
	fixed := time.Unix(1_000_000, 0).UTC()
	tests := []struct {
		name string
		ind  indicator.Indicator
		want time.Time
	}{
		{
			name: "published_date wins over last_updated",
			ind:  indicator.Indicator{"published_date": 1700000000.0, "last_updated": 1600000000.0},
			want: time.Unix(1700000000, 0).UTC(),
		},
		{
			name: "last_updated used when no published_date",
			ind:  indicator.Indicator{"last_updated": 1600000000.0},
			want: time.Unix(1600000000, 0).UTC(),
		},
		{
			name: "zero published_date falls through to last_updated",
			ind:  indicator.Indicator{"published_date": 0.0, "last_updated": 1600000000.0},
			want: time.Unix(1600000000, 0).UTC(),
		},
		{
			name: "numeric string is parsed",
			ind:  indicator.Indicator{"published_date": "1700000000"},
			want: time.Unix(1700000000, 0).UTC(),
		},
		{
			name: "no usable field falls back to now",
			ind:  indicator.Indicator{"type": "domain"},
			want: fixed,
		},
		{
			name: "unparseable string falls back to now",
			ind:  indicator.Indicator{"published_date": "not-a-number"},
			want: fixed,
		},
	}

	c := &Client{now: func() time.Time { return fixed }}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := c.indicatorTime(tc.ind, fixed); !got.Equal(tc.want) {
				t.Errorf("indicatorTime = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestResetSessionRebuildsClient(t *testing.T) {
	t.Parallel()
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

// stubRoundTripper adapts a function to http.RoundTripper so New can be
// exercised without real network I/O.
type stubRoundTripper func(*http.Request) (*http.Response, error)

func (f stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// jsonResponse builds an HTTP response carrying body encoded as JSON.
func jsonResponse(status int, body any) *http.Response {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(&buf),
		Header:     make(http.Header),
	}
}

// TestNewBuildsClientWithoutNetwork verifies New builds a client for the
// configured region and instance and performs no network I/O.
func TestNewBuildsClientWithoutNetwork(t *testing.T) {
	// Swap the credential and transport seams so New runs without a real
	// service account, and fail the test if it reaches the network: New must
	// perform no I/O.
	origCreds := credentialsFromJSON
	origTransport := transportBase
	t.Cleanup(func() {
		credentialsFromJSON = origCreds
		transportBase = origTransport
	})
	credentialsFromJSON = func(_ context.Context, _ []byte, _ google.CredentialsType, _ ...string) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})}, nil
	}
	transportBase = func() http.RoundTripper {
		return stubRoundTripper(func(r *http.Request) (*http.Response, error) {
			t.Errorf("New made an unexpected network call to %s", r.URL)
			return jsonResponse(http.StatusOK, struct{}{}), nil
		})
	}

	c, err := New(context.Background(), Config{
		CustomerID:     "cust-1",
		Region:         "us",
		Project:        "proj-1",
		CredentialJSON: []byte(`{"type":"service_account"}`),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if want := "https://us-chronicle.googleapis.com"; c.baseURL != want {
		t.Errorf("baseURL = %q, want %q", c.baseURL, want)
	}
	if c.instancePath != testInstancePath {
		t.Errorf("instancePath = %q, want %q", c.instancePath, testInstancePath)
	}
}

func TestNewValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"unknown region", Config{Region: "narnia", Project: "proj-1", CustomerID: "cust-1"}},
		{"missing project", Config{Region: "us", CustomerID: "cust-1"}},
		{"missing customer ID", Config{Region: "us", Project: "proj-1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(context.Background(), tc.cfg); err == nil {
				t.Errorf("New(%+v) returned nil error, want validation failure", tc.cfg)
			}
		})
	}
}

// TestResolveCredentials verifies credential loading dispatches on the supplied
// credential JSON: an explicit service account or external_account (WIF) document
// is loaded for its declared type, an empty document falls back to Application
// Default Credentials, and an unsupported or malformed document is rejected.
func TestResolveCredentials(t *testing.T) {
	stubCreds := &google.Credentials{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})}
	tests := []struct {
		name     string
		credJSON []byte
		wantErr  bool
		wantADC  bool                   // expect the ADC fallback
		wantType google.CredentialsType // type passed to the JSON loader
	}{
		{name: "service account loads typed", credJSON: []byte(`{"type":"service_account"}`), wantType: google.ServiceAccount},
		{name: "external account (WIF) loads typed", credJSON: []byte(`{"type":"external_account"}`), wantType: google.ExternalAccount},
		{name: "empty falls back to ADC", credJSON: nil, wantADC: true},
		{name: "unsupported type rejected", credJSON: []byte(`{"type":"authorized_user"}`), wantErr: true},
		{name: "malformed JSON rejected", credJSON: []byte(`{not json`), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origJSON := credentialsFromJSON
			origADC := findDefaultCredentials
			t.Cleanup(func() {
				credentialsFromJSON = origJSON
				findDefaultCredentials = origADC
			})

			var gotType google.CredentialsType
			var jsonCalled, adcCalled bool
			credentialsFromJSON = func(_ context.Context, _ []byte, credType google.CredentialsType, _ ...string) (*google.Credentials, error) {
				jsonCalled, gotType = true, credType
				return stubCreds, nil
			}
			findDefaultCredentials = func(_ context.Context, _ ...string) (*google.Credentials, error) {
				adcCalled = true
				return stubCreds, nil
			}

			creds, err := resolveCredentials(context.Background(), tc.credJSON)
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveCredentials error = %v, wantErr %t", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if creds != stubCreds {
				t.Error("resolveCredentials returned unexpected credentials")
			}
			if adcCalled != tc.wantADC {
				t.Errorf("findDefaultCredentials called = %t, want %t", adcCalled, tc.wantADC)
			}
			if tc.wantADC {
				if jsonCalled {
					t.Error("credentialsFromJSON was called on the ADC path")
				}
				return
			}
			if !jsonCalled {
				t.Error("credentialsFromJSON was not called for explicit credential JSON")
			}
			if gotType != tc.wantType {
				t.Errorf("credentialsFromJSON type = %q, want %q", gotType, tc.wantType)
			}
		})
	}
}

// TestSendRateLimitedError verifies a 429 response wraps ErrRateLimited so the
// writer can apply the API's mandated minimum retry delay, and is not classified
// as permanent.
func TestSendRateLimitedError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "slow down")
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.Send(context.Background(), []indicator.Indicator{{"id": "ind-1"}})
	if err == nil {
		t.Fatal("Send returned nil error on 429")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("errors.Is(err, ErrRateLimited) = false, want true (err: %v)", err)
	}
	if errors.Is(err, ErrPermanent) {
		t.Errorf("429 must not be classified as permanent (err: %v)", err)
	}
}

// TestIsPermanentStatus pins the retry classification: a request-level client
// error will not clear on retry, while auth, rate-limit, timeout, and server
// statuses are treated as transient so the writer keeps retrying them.
func TestIsPermanentStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code int
		want bool
	}{
		{"bad request", http.StatusBadRequest, true},
		{"forbidden", http.StatusForbidden, true},
		{"not found", http.StatusNotFound, true},
		{"method not allowed", http.StatusMethodNotAllowed, true},
		{"conflict", http.StatusConflict, true},
		{"gone", http.StatusGone, true},
		{"payload too large", http.StatusRequestEntityTooLarge, true},
		{"unprocessable", http.StatusUnprocessableEntity, true},
		{"unauthorized is transient", http.StatusUnauthorized, false},
		{"request timeout is transient", http.StatusRequestTimeout, false},
		{"too many requests is transient", http.StatusTooManyRequests, false},
		{"internal error is transient", http.StatusInternalServerError, false},
		{"unavailable is transient", http.StatusServiceUnavailable, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isPermanentStatus(tc.code); got != tc.want {
				t.Errorf("isPermanentStatus(%d) = %t, want %t", tc.code, got, tc.want)
			}
		})
	}
}

// TestIsPermanentCode pins the retry classification of the status code an
// already-completed operation carries: a fixed request problem is permanent,
// while auth, rate-limit, timeout, abort, and server-side codes stay transient.
func TestIsPermanentCode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code int
		want bool
	}{
		{"invalid argument", 3, true},
		{"not found", 5, true},
		{"already exists", 6, true},
		{"permission denied", 7, true},
		{"failed precondition", 9, true},
		{"out of range", 11, true},
		{"unimplemented", 12, true},
		{"ok is not permanent", 0, false},
		{"cancelled is transient", 1, false},
		{"deadline exceeded is transient", 4, false},
		{"resource exhausted is transient", 8, false},
		{"aborted is transient", 10, false},
		{"internal is transient", 13, false},
		{"unavailable is transient", 14, false},
		{"unauthenticated is transient", 16, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isPermanentCode(tc.code); got != tc.want {
				t.Errorf("isPermanentCode(%d) = %t, want %t", tc.code, got, tc.want)
			}
		})
	}
}

// TestSendPermanentVsTransientError verifies that a permanent status wraps
// ErrPermanent so a caller can stop retrying, while a transient status does not.
func TestSendPermanentVsTransientError(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		wantPermanent bool
	}{
		{"forbidden is permanent", http.StatusForbidden, true},
		{"bad request is permanent", http.StatusBadRequest, true},
		{"unauthorized is retryable", http.StatusUnauthorized, false},
		{"rate limited is retryable", http.StatusTooManyRequests, false},
		{"server error is retryable", http.StatusInternalServerError, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, "upstream said no")
			}))
			defer srv.Close()

			c := newTestClient(srv)
			err := c.Send(context.Background(), []indicator.Indicator{{"id": "ind-1"}})
			if err == nil {
				t.Fatalf("Send returned nil error on %d", tc.status)
			}
			if got := errors.Is(err, ErrPermanent); got != tc.wantPermanent {
				t.Errorf("errors.Is(err, ErrPermanent) = %t, want %t (err: %v)", got, tc.wantPermanent, err)
			}
		})
	}
}

// TestSendOperationError covers the import response body: a 2xx that carries a
// completed operation with an embedded error must surface that error, wrapping
// ErrPermanent only for a permanent status code, while an empty body or an
// operation with no error is a successful delivery.
func TestSendOperationError(t *testing.T) {
	tests := []struct {
		name          string
		body          string // operation JSON to write; empty writes no body
		wantErr       bool
		wantPermanent bool
	}{
		{name: "empty body is accepted", body: "", wantErr: false},
		{name: "operation without error is accepted", body: `{"done":true}`, wantErr: false},
		{
			name:          "permanent operation code stops retries",
			body:          `{"done":true,"error":{"code":7,"message":"permission denied"}}`,
			wantErr:       true,
			wantPermanent: true,
		},
		{
			name:          "transient operation code is retryable",
			body:          `{"done":true,"error":{"code":14,"message":"service unavailable"}}`,
			wantErr:       true,
			wantPermanent: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				if tc.body != "" {
					_, _ = io.WriteString(w, tc.body)
				}
			}))
			defer srv.Close()

			c := newTestClient(srv)
			err := c.Send(context.Background(), []indicator.Indicator{{"id": "ind-1"}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Send error = %v, wantErr %t", err, tc.wantErr)
			}
			if err == nil {
				return
			}
			if got := errors.Is(err, ErrPermanent); got != tc.wantPermanent {
				t.Errorf("errors.Is(err, ErrPermanent) = %t, want %t (err: %v)", got, tc.wantPermanent, err)
			}
		})
	}
}

// TestEpochTime covers the epoch-seconds conversion, including the fractional
// path where sub-second precision must survive into the resulting nanoseconds,
// and the cases that yield ok=false so the caller falls through to the next
// timestamp field.
func TestEpochTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		v    any
		want time.Time
		ok   bool
	}{
		{"whole float seconds", 1700000000.0, time.Unix(1700000000, 0).UTC(), true},
		{"fractional float seconds", 1700000000.5, time.Unix(1700000000, 500000000).UTC(), true},
		{"whole numeric string", "1700000000", time.Unix(1700000000, 0).UTC(), true},
		{"fractional numeric string", "1700000000.25", time.Unix(1700000000, 250000000).UTC(), true},
		{"zero is not usable", 0.0, time.Time{}, false},
		{"unparseable string", "not-a-number", time.Time{}, false},
		{"wrong type", true, time.Time{}, false},
		{"missing value", nil, time.Time{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := epochTime(tc.v)
			if ok != tc.ok {
				t.Fatalf("epochTime(%v) ok = %t, want %t", tc.v, ok, tc.ok)
			}
			if ok && !got.Equal(tc.want) {
				t.Errorf("epochTime(%v) = %s, want %s", tc.v, got, tc.want)
			}
		})
	}
}

// TestImportChunkEnd verifies the size-bounded split: a single entry larger than
// the budget is still sent on its own, budget-filling entries go one per request,
// and small entries pack together — including from a mid-slice start.
func TestImportChunkEnd(t *testing.T) {
	t.Parallel()
	entry := func(dataLen int) logEntry { return logEntry{Data: strings.Repeat("a", dataLen)} }
	// An entry whose encoded size (data + overhead) equals the whole budget, so
	// two of them cannot share a request.
	fullData := maxImportBytes - perEntryOverheadBytes

	tests := []struct {
		name    string
		entries []logEntry
		start   int
		want    int
	}{
		{"single oversized entry is sent alone", []logEntry{entry(maxImportBytes * 2)}, 0, 1},
		{"budget-filling entries split one per request", []logEntry{entry(fullData), entry(fullData)}, 0, 1},
		{"small entries pack into one request", []logEntry{entry(10), entry(10), entry(10)}, 0, 3},
		{"boundary respected from a mid-slice start", []logEntry{entry(fullData), entry(fullData), entry(10)}, 1, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := importChunkEnd(tc.entries, tc.start); got != tc.want {
				t.Errorf("importChunkEnd(..., %d) = %d, want %d", tc.start, got, tc.want)
			}
		})
	}
}

// TestNewRoutesRegionToHostAndInstancePath verifies New maps the configured
// region to both the {region}-chronicle host and the locations/{region} segment
// of the instance path, for a legacy alias and a Google Cloud region as well as
// the distinct eu multi-region — not only the us default the other tests cover.
func TestNewRoutesRegionToHostAndInstancePath(t *testing.T) {
	origCreds := credentialsFromJSON
	origTransport := transportBase
	t.Cleanup(func() {
		credentialsFromJSON = origCreds
		transportBase = origTransport
	})
	credentialsFromJSON = func(_ context.Context, _ []byte, _ google.CredentialsType, _ ...string) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test"})}, nil
	}
	transportBase = func() http.RoundTripper {
		return stubRoundTripper(func(r *http.Request) (*http.Response, error) {
			t.Errorf("New made an unexpected network call to %s", r.URL)
			return jsonResponse(http.StatusOK, struct{}{}), nil
		})
	}

	tests := []struct {
		name       string
		region     string
		wantHost   string
		wantRegion string // the locations/{region} path segment
	}{
		{"legacy EU alias", "EU", "https://europe-chronicle.googleapis.com", "europe"},
		{"gcp region", "asia-south1", "https://asia-south1-chronicle.googleapis.com", "asia-south1"},
		{"eu multi-region", "eu", "https://eu-chronicle.googleapis.com", "eu"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(context.Background(), Config{
				CustomerID:     "cust-1",
				Region:         tc.region,
				Project:        "proj-1",
				CredentialJSON: []byte(`{"type":"service_account"}`),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if c.baseURL != tc.wantHost {
				t.Errorf("baseURL = %q, want %q", c.baseURL, tc.wantHost)
			}
			wantPath := "projects/proj-1/locations/" + tc.wantRegion + "/instances/cust-1"
			if c.instancePath != wantPath {
				t.Errorf("instancePath = %q, want %q", c.instancePath, wantPath)
			}
		})
	}
}

// TestSendMalformedSuccessBody covers the 2xx-with-unparseable-body path: a
// success status carrying a body that is neither empty nor valid JSON surfaces a
// decode error rather than being silently treated as acceptance, and is not
// classified as permanent or rate limited.
func TestSendMalformedSuccessBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{not valid json")
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.Send(context.Background(), []indicator.Indicator{{"id": "ind-1"}})
	if err == nil {
		t.Fatal("Send returned nil on a malformed 2xx body")
	}
	if errors.Is(err, ErrPermanent) || errors.Is(err, ErrRateLimited) {
		t.Errorf("malformed success body must not be classified permanent/rate-limited (err: %v)", err)
	}
}
