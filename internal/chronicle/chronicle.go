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

// Package chronicle forwards CrowdStrike indicators to Google Chronicle's
// logs:import API, authenticating with a Google service account and routing to
// the regional endpoint for the configured Chronicle region.
package chronicle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

// logType is the Chronicle log type under which CCIB ingests every indicator.
const logType = "CROWDSTRIKE_IOC"

// apiVersion is the Chronicle API version used for log import.
const apiVersion = "v1"

// defaultRegion serves the US multi-region and is used for an empty region.
const defaultRegion = "us"

// timeFormat renders a timestamp as RFC 3339 with six fractional-second digits
// in UTC, the representation the import API expects for log entry and
// collection times.
const timeFormat = "2006-01-02T15:04:05.000000Z07:00"

// connectTimeout and requestTimeout bound the TCP dial and the overall request.
// The import API's documented recommendation is a 60-second request timeout, so
// a large batch does not time out on the client before the server responds.
const (
	connectTimeout = 10 * time.Second
	requestTimeout = 60 * time.Second
)

// oauthScopes is the single Cloud Platform scope the service account token is
// minted for; it covers log import.
var oauthScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
}

// ErrPermanent marks a response that will not succeed on retry, such as a
// malformed request or a denied permission. A caller that retries on failure
// can test for it with errors.Is and stop early instead of re-sending an
// identical request that is certain to fail again. Responses that may clear on
// their own — timeouts, rate limits, transient auth, and server errors — are
// not wrapped with it.
var ErrPermanent = errors.New("chronicle: non-retryable response")

// ErrRateLimited marks a response rejected for rate limiting (HTTP 429). It is a
// retryable error, but the import API requires a minimum delay of 30 seconds
// before retrying a 429, longer than the early exponential-backoff steps. A
// caller can test for it with errors.Is and lengthen its wait accordingly.
var ErrRateLimited = errors.New("chronicle: rate limited")

// credentialsFromJSON parses an explicit Google credential JSON document of a
// known type into OAuth2 credentials. findDefaultCredentials resolves
// Application Default Credentials from the environment. Both are package
// variables so tests can supply a static token source and exercise New without
// real credentials.
var (
	credentialsFromJSON    = google.CredentialsFromJSONWithType
	findDefaultCredentials = google.FindDefaultCredentials
)

// transportBase builds the base RoundTripper that the OAuth2 transport wraps. It
// is a package variable so tests can serve canned responses without real network
// I/O.
var transportBase = func() http.RoundTripper {
	return &http.Transport{
		DialContext: (&net.Dialer{Timeout: connectTimeout}).DialContext,
	}
}

// regionCanon maps an accepted region token (upper-cased) to its canonical
// Google Cloud region, which is what the new API keys the host and location on.
// Legacy Chronicle region codes and the Google Cloud regions Chronicle serves
// are both present; a region resolves to a host of the form
// {region}-chronicle.googleapis.com and reappears as the location segment of the
// instance path.
var regionCanon = map[string]string{
	// Legacy Chronicle region codes.
	"EU": "europe",
	"UK": "europe-west2",
	"IL": "me-west1",
	"AU": "australia-southeast1",
	"SG": "asia-southeast1",
	// Google Cloud regions, keyed by their own upper-cased form.
	"US":                      defaultRegion,
	"EUROPE":                  "europe",
	"EUROPE-WEST2":            "europe-west2",
	"EUROPE-WEST3":            "europe-west3",
	"EUROPE-WEST6":            "europe-west6",
	"EUROPE-WEST9":            "europe-west9",
	"EUROPE-WEST12":           "europe-west12",
	"EUROPE-CENTRAL2":         "europe-central2",
	"ME-WEST1":                "me-west1",
	"ME-CENTRAL1":             "me-central1",
	"ME-CENTRAL2":             "me-central2",
	"AFRICA-SOUTH1":           "africa-south1",
	"ASIA-SOUTH1":             "asia-south1",
	"ASIA-EAST1":              "asia-east1",
	"ASIA-SOUTHEAST1":         "asia-southeast1",
	"ASIA-SOUTHEAST2":         "asia-southeast2",
	"ASIA-NORTHEAST1":         "asia-northeast1",
	"ASIA-NORTHEAST3":         "asia-northeast3",
	"AUSTRALIA-SOUTHEAST1":    "australia-southeast1",
	"SOUTHAMERICA-EAST1":      "southamerica-east1",
	"NORTHAMERICA-NORTHEAST2": "northamerica-northeast2",
}

// regionExact resolves region tokens that must be matched case-sensitively,
// because case is the only thing that tells them apart from a legacy alias.
// Google documents "eu" as a multi-region endpoint of its own, distinct from
// "europe"; the legacy Chronicle code "EU" denotes the European instance and
// resolves to "europe". Upper-casing would merge the two, so the lower-case "eu"
// is resolved here, ahead of the case-insensitive table, while the upper-cased
// legacy "EU" falls through to it.
var regionExact = map[string]string{
	"eu": "eu",
}

// canonicalRegion resolves a configured region to its canonical Google Cloud
// region, reporting ok=false for a non-empty region that is neither a known
// legacy alias nor a known Google Cloud region. An empty region defaults to the
// US multi-region, and underscores are accepted in place of hyphens.
func canonicalRegion(region string) (string, bool) {
	r := strings.TrimSpace(region)
	if r == "" {
		return defaultRegion, true
	}
	r = strings.ReplaceAll(r, "_", "-")
	if canon, ok := regionExact[r]; ok {
		return canon, true
	}
	if canon, ok := regionCanon[strings.ToUpper(r)]; ok {
		return canon, true
	}
	return "", false
}

// ValidateRegion reports whether region is one CCIB can route to, so an unknown
// value fails fast at startup rather than producing an unresolvable host at
// send time. An empty region is valid and defaults to the US multi-region.
func ValidateRegion(region string) error {
	if _, ok := canonicalRegion(region); !ok {
		return fmt.Errorf("chronicle: unknown region %q", region)
	}
	return nil
}

// Config holds the Chronicle destination settings and the credentials used to
// authenticate to it.
type Config struct {
	CustomerID string
	Region     string
	Project    string
	// CredentialJSON is a Google credential document: either a service account
	// key or an external_account (Workload Identity Federation) configuration.
	// When empty, New falls back to Application Default Credentials, which honor
	// GOOGLE_APPLICATION_CREDENTIALS and the ambient Google Cloud environment.
	CredentialJSON []byte
}

// maxImportBytes bounds the estimated size of a single logs:import request body.
// base64 inflates each indicator by roughly a third, so a batch bounded only by
// count can still exceed Chronicle's import request-size limit. The import API's
// hard limit is 4 MB uncompressed per request and its documented ideal batch is
// about 2 MB, so this budget targets that ideal: it halves the request count
// versus a smaller bound while staying well clear of the hard limit.
const maxImportBytes = 2 * 1024 * 1024

// perEntryOverheadBytes approximates the non-payload bytes each log entry adds to
// an import request: the two RFC 3339 timestamps plus the JSON field names,
// quoting, and separators that wrap the base64 data.
const perEntryOverheadBytes = 160

// logEntry is a single log in an import request: the base64-encoded indicator
// JSON with its event time and a collection time that is never earlier than the
// event time.
type logEntry struct {
	Data           string `json:"data"`
	LogEntryTime   string `json:"log_entry_time"`
	CollectionTime string `json:"collection_time"`
}

// inlineSource carries the logs of an import request.
type inlineSource struct {
	Logs []logEntry `json:"logs"`
}

// importRequest is the body posted to the logs:import endpoint.
type importRequest struct {
	InlineSource inlineSource `json:"inline_source"`
}

// importOperation models the subset of a google.longrunning.Operation error that
// a logs:import call could carry. The v1 ImportLogs method answers a successful
// import with an empty body and does not return an operation, so in practice this
// decodes to the zero value and the 2xx alone is the acceptance signal. The type
// is retained as a defensive decode: should any error payload arrive in the body,
// its completed-with-error field is surfaced as the batch's real outcome rather
// than being silently swallowed. Any other shape decodes to acceptance.
type importOperation struct {
	Error *operationStatus `json:"error"`
}

// operationStatus is the google.rpc.Status a failed operation carries: a numeric
// code and a human-readable message.
type operationStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Client posts batches of indicators to a Chronicle instance over an
// OAuth2-authorized HTTP client. It is safe for use by a single writer.
type Client struct {
	baseURL      string
	instancePath string
	newClient    func() *http.Client
	http         *http.Client
	now          func() time.Time
}

// New builds a Client that authenticates with the given credentials and targets
// the logs:import endpoint for the configured region and instance. It validates
// the region, project, and customer ID, then loads credentials — from the
// supplied credential JSON, or from Application Default Credentials when none is
// given; it performs no network I/O.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := ValidateRegion(cfg.Region); err != nil {
		return nil, err
	}
	region, _ := canonicalRegion(cfg.Region)
	if cfg.Project == "" {
		return nil, errors.New("chronicle: project is required")
	}
	if cfg.CustomerID == "" {
		return nil, errors.New("chronicle: customer ID is required")
	}

	instancePath := fmt.Sprintf("projects/%s/locations/%s/instances/%s", cfg.Project, region, cfg.CustomerID)

	creds, err := resolveCredentials(ctx, cfg.CredentialJSON)
	if err != nil {
		return nil, err
	}

	newClient := authorizedClientFactory(creds.TokenSource)
	return &Client{
		baseURL:      "https://" + region + "-chronicle.googleapis.com",
		instancePath: instancePath,
		newClient:    newClient,
		http:         newClient(),
		now:          time.Now,
	}, nil
}

// importURL is the logs:import endpoint for this client's instance.
func (c *Client) importURL() string {
	return c.baseURL + "/" + apiVersion + "/" + c.instancePath + "/logTypes/" + logType + "/logs:import"
}

// resolveCredentials loads OAuth2 credentials for the import client. When
// credential JSON is supplied it is loaded for its declared type — a Google
// service account key or an external_account (Workload Identity Federation)
// configuration — so a WIF credential file is accepted, not only a service
// account key. When no JSON is supplied it falls back to Application Default
// Credentials, which honor GOOGLE_APPLICATION_CREDENTIALS and the ambient Google
// Cloud environment.
func resolveCredentials(ctx context.Context, credJSON []byte) (*google.Credentials, error) {
	if len(credJSON) == 0 {
		creds, err := findDefaultCredentials(ctx, oauthScopes...)
		if err != nil {
			return nil, fmt.Errorf("chronicle: loading application default credentials: %w", err)
		}
		return creds, nil
	}
	credType, err := credentialType(credJSON)
	if err != nil {
		return nil, err
	}
	creds, err := credentialsFromJSON(ctx, credJSON, credType, oauthScopes...)
	if err != nil {
		return nil, fmt.Errorf("chronicle: loading credentials: %w", err)
	}
	return creds, nil
}

// credentialType reads the type declared in a Google credential JSON document
// and admits only the two CCIB expects: a service account key and an
// external_account (Workload Identity Federation) configuration. An explicit
// allowlist keeps an unexpected credential type from being loaded
// unintentionally.
func credentialType(credJSON []byte) (google.CredentialsType, error) {
	var doc struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(credJSON, &doc); err != nil {
		return "", fmt.Errorf("chronicle: parsing credential JSON: %w", err)
	}
	switch google.CredentialsType(doc.Type) {
	case google.ServiceAccount:
		return google.ServiceAccount, nil
	case google.ExternalAccount:
		return google.ExternalAccount, nil
	default:
		return "", fmt.Errorf("chronicle: unsupported credential type %q: expected %q or %q",
			doc.Type, google.ServiceAccount, google.ExternalAccount)
	}
}

// jsonCall describes a single JSON request/response exchange. op is a short
// label naming the operation; it appears in error messages in place of the URL
// so failures read cleanly rather than echoing a long request URL.
type jsonCall struct {
	method string
	url    string
	op     string
	body   any
	out    any
}

// doJSON performs the HTTP request described by call with the request timeout
// applied, encoding body as JSON when non-nil and decoding a JSON response into
// out when non-nil. A non-2xx status becomes an error carrying a bounded
// response snippet. Errors identify the request by call.op only.
func (c *Client) doJSON(ctx context.Context, call jsonCall) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var reader io.Reader
	if call.body != nil {
		encoded, err := json.Marshal(call.body)
		if err != nil {
			return fmt.Errorf("chronicle: encoding %s request: %w", call.op, err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(reqCtx, call.method, call.url, reader)
	if err != nil {
		return fmt.Errorf("chronicle: building %s request: %w", call.op, err)
	}
	if call.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("chronicle: %s: %w", call.op, err)
	}
	defer drainClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := strings.TrimSpace(string(snippet))
		switch {
		case isPermanentStatus(resp.StatusCode):
			return fmt.Errorf("chronicle: %s returned %s: %s: %w", call.op, resp.Status, msg, ErrPermanent)
		case resp.StatusCode == http.StatusTooManyRequests:
			return fmt.Errorf("chronicle: %s returned %s: %s: %w", call.op, resp.Status, msg, ErrRateLimited)
		default:
			return fmt.Errorf("chronicle: %s returned %s: %s", call.op, resp.Status, msg)
		}
	}

	if call.out != nil {
		// A successful call may answer with an empty body when there is nothing
		// for the caller to read; that decodes to EOF, which is not a failure.
		if err := json.NewDecoder(resp.Body).Decode(call.out); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("chronicle: decoding %s response: %w", call.op, err)
		}
	}
	return nil
}

// isPermanentStatus reports whether an HTTP status will not clear on retry of
// the same request. Client errors that reflect a fixed problem with the request
// or its permissions are permanent; an unauthorized status is treated as
// transient because a session reset can mint a fresh token, and rate limiting,
// request timeout, and server errors are all expected to recover on their own.
// A payload that exceeds the request-size limit and a resource that is gone will
// not clear by resending the identical request, so both are permanent: retrying
// them only stalls the pipeline behind a request the server keeps rejecting.
func isPermanentStatus(code int) bool {
	switch code {
	case http.StatusBadRequest,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusConflict,
		http.StatusGone,
		http.StatusRequestEntityTooLarge,
		http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

// isPermanentCode reports whether a google.rpc.Code carried by a completed
// operation reflects a fixed problem with the request that a retry cannot clear,
// mirroring how isPermanentStatus classifies HTTP statuses. Codes that may
// recover on their own — an unauthenticated call a fresh token can fix, rate
// limits, timeouts, aborts, and server-side faults — are treated as transient.
func isPermanentCode(code int) bool {
	switch code {
	case 3, // INVALID_ARGUMENT
		5,  // NOT_FOUND
		6,  // ALREADY_EXISTS
		7,  // PERMISSION_DENIED
		9,  // FAILED_PRECONDITION
		11, // OUT_OF_RANGE
		12: // UNIMPLEMENTED
		return true
	default:
		return false
	}
}

// authorizedClientFactory returns a function that builds a fresh HTTP client
// which injects a bearer token from ts and bounds the TCP dial. A factory (not
// a single client) lets ResetSession rebuild the client without a context.
func authorizedClientFactory(ts oauth2.TokenSource) func() *http.Client {
	return func() *http.Client {
		return &http.Client{
			Transport: &oauth2.Transport{Source: ts, Base: transportBase()},
		}
	}
}

// ResetSession rebuilds the authorized HTTP client, discarding any pooled TCP
// connections so the next send dials afresh. It reuses the existing OAuth2 token
// source, so a cached, still-valid token is kept and a new token is minted only
// once the current one expires. The writer calls this after repeated send
// failures to recover from a wedged connection.
func (c *Client) ResetSession() {
	c.http = c.newClient()
}

// Send posts a batch of indicators to Chronicle as CROWDSTRIKE_IOC logs.
// Each indicator is forwarded verbatim as base64-encoded JSON with an event
// time derived from its published_date or last_updated field and a collection
// time that is strictly after the event time, as the import API requires. It
// returns an error on any non-2xx response so the caller can retry. A 2xx
// response acknowledges that the batch was accepted; when that response carries a
// long-running operation that has already completed with an error, that error is
// the batch's real outcome and is returned — as a permanent error when its status
// code reflects a fixed problem with the request, otherwise as a retryable one.
// An operation still in progress, or an empty body, is treated as acceptance:
// delivery is at-least-once, so any indicator that did not land is re-fetched and
// de-duplicated on a later cycle.
//
// base64 expansion can push a large batch past Chronicle's import request-size
// limit, so Send marshals each indicator once and splits the encoded entries into
// sub-requests bounded by maxImportBytes. A failure on any sub-request fails the
// whole Send; the caller retries the batch and at-least-once delivery covers the
// entries that already landed.
func (c *Client) Send(ctx context.Context, batch []indicator.Indicator) error {
	now := c.now().UTC()
	entries := make([]logEntry, 0, len(batch))
	for _, ind := range batch {
		raw, err := json.Marshal(ind)
		if err != nil {
			return fmt.Errorf("chronicle: encoding indicator: %w", err)
		}
		eventTime := c.indicatorTime(ind, now)
		// The import API requires the collection time to be strictly after the
		// log entry time. Use the current time when it already is; otherwise
		// nudge just past the event by one microsecond, the smallest step the
		// rendered timestamp can represent, so the two never format as equal.
		collectionTime := now
		if !collectionTime.After(eventTime) {
			collectionTime = eventTime.Add(time.Microsecond)
		}
		entries = append(entries, logEntry{
			Data:           base64.StdEncoding.EncodeToString(raw),
			LogEntryTime:   eventTime.Format(timeFormat),
			CollectionTime: collectionTime.Format(timeFormat),
		})
	}

	endpoint := c.importURL()
	for start := 0; start < len(entries); {
		end := importChunkEnd(entries, start)
		if err := c.importLogs(ctx, endpoint, entries[start:end]); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// importChunkEnd returns the exclusive end index of the sub-request beginning at
// start, bounded by an estimated encoded size of maxImportBytes. At least one
// entry is always included, so a single entry larger than the budget is still
// sent on its own rather than stalling the batch.
func importChunkEnd(entries []logEntry, start int) int {
	total := 0
	end := start
	for end < len(entries) {
		size := len(entries[end].Data) + perEntryOverheadBytes
		if end > start && total+size > maxImportBytes {
			break
		}
		total += size
		end++
	}
	return end
}

// importLogs posts one sub-request of encoded log entries to the logs:import
// endpoint and interprets the response, surfacing an operation that completed
// with an error as the sub-request's outcome — permanent when its code reflects a
// fixed request problem, otherwise retryable.
func (c *Client) importLogs(ctx context.Context, endpoint string, logs []logEntry) error {
	body := importRequest{
		InlineSource: inlineSource{Logs: logs},
	}

	slog.Debug("posting indicators to chronicle",
		"component", "chronicle",
		"endpoint", endpoint,
		"count", len(logs),
	)

	var op importOperation
	if err := c.doJSON(ctx, jsonCall{method: http.MethodPost, url: endpoint, op: "logs:import", body: body, out: &op}); err != nil {
		return err
	}
	if op.Error != nil {
		if isPermanentCode(op.Error.Code) {
			return fmt.Errorf("chronicle: logs:import operation failed (code %d): %s: %w", op.Error.Code, op.Error.Message, ErrPermanent)
		}
		return fmt.Errorf("chronicle: logs:import operation failed (code %d): %s", op.Error.Code, op.Error.Message)
	}

	slog.Debug("chronicle accepted batch",
		"component", "chronicle",
		"count", len(logs),
	)
	return nil
}

// indicatorTime returns the event time for an indicator, preferring
// published_date, then last_updated, and finally the supplied fallback when
// neither field carries a usable value. The caller passes a single pre-read
// clock value so every indicator in a batch shares one "now" and the no-timestamp
// path does not read the clock again.
func (c *Client) indicatorTime(ind indicator.Indicator, fallback time.Time) time.Time {
	for _, field := range []string{"published_date", "last_updated"} {
		if t, ok := epochTime(ind[field]); ok {
			return t
		}
	}
	return fallback
}

// epochTime converts a Falcon Unix-epoch-seconds value into a time.Time.
// Indicators are decoded with the standard JSON decoder, so a numeric field
// arrives as a float64 and a numeric string as a string; both are handled. A
// zero, missing, or unparseable value yields ok=false so the caller can fall
// through to the next field.
func epochTime(v any) (time.Time, bool) {
	var secs float64
	switch x := v.(type) {
	case float64:
		secs = x
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return time.Time{}, false
		}
		secs = f
	default:
		return time.Time{}, false
	}
	if secs == 0 {
		return time.Time{}, false
	}
	whole := int64(secs)
	frac := int64((secs - float64(whole)) * 1e9)
	return time.Unix(whole, frac).UTC(), true
}

// drainClose consumes and closes a response body so the connection can be
// reused by the transport's pool.
func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
