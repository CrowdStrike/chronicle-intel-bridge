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
// unstructured log ingestion API, authenticating with a Google service account
// and routing to the regional endpoint for the configured Chronicle region.
package chronicle

import (
	"bytes"
	"context"
	"encoding/json"
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

// endpointPath is the ingestion API path appended to each regional host.
const endpointPath = "/v2/unstructuredlogentries:batchCreate"

// defaultHost serves the US multi-region and is used for any region that is
// empty or unrecognized, matching the original service's fallback.
const defaultHost = "malachiteingestion-pa.googleapis.com"

// connectTimeout and requestTimeout bound the TCP dial and the overall request,
// mirroring the (connect, read) timeout pair of the original service.
const (
	connectTimeout = 10 * time.Second
	requestTimeout = 30 * time.Second
)

// oauthScopes are the Chronicle ingestion and backstory scopes the service
// account token is minted for.
var oauthScopes = []string{
	"https://www.googleapis.com/auth/chronicle-backstory",
	"https://www.googleapis.com/auth/malachite-ingestion",
}

// Ingestion hosts shared by a legacy region code and its Google Cloud region
// code, named once so the two keys cannot drift apart.
const (
	hostEurope              = "europe-malachiteingestion-pa.googleapis.com"
	hostEuropeWest2         = "europe-west2-malachiteingestion-pa.googleapis.com"
	hostMEWest1             = "me-west1-malachiteingestion-pa.googleapis.com"
	hostAustraliaSoutheast1 = "australia-southeast1-malachiteingestion-pa.googleapis.com"
	hostAsiaSoutheast1      = "asia-southeast1-malachiteingestion-pa.googleapis.com"
)

// regionHosts maps a Chronicle region code (upper-cased) to its ingestion host.
// It covers both the legacy region codes and the newer Google Cloud region
// codes; US and any unmatched region resolve to defaultHost.
var regionHosts = map[string]string{
	"EU": hostEurope,
	"UK": hostEuropeWest2,
	"IL": hostMEWest1,
	"AU": hostAustraliaSoutheast1,
	"SG": hostAsiaSoutheast1,

	"US":                      defaultHost,
	"EUROPE":                  hostEurope,
	"EUROPE-WEST2":            hostEuropeWest2,
	"EUROPE-WEST3":            "europe-west3-malachiteingestion-pa.googleapis.com",
	"EUROPE-WEST6":            "europe-west6-malachiteingestion-pa.googleapis.com",
	"EUROPE-WEST9":            "europe-west9-malachiteingestion-pa.googleapis.com",
	"EUROPE-WEST12":           "europe-west12-malachiteingestion-pa.googleapis.com",
	"ME-WEST1":                hostMEWest1,
	"ME-CENTRAL1":             "me-central1-malachiteingestion-pa.googleapis.com",
	"ME-CENTRAL2":             "me-central2-malachiteingestion-pa.googleapis.com",
	"ASIA-SOUTH1":             "asia-south1-malachiteingestion-pa.googleapis.com",
	"ASIA-SOUTHEAST1":         hostAsiaSoutheast1,
	"ASIA-NORTHEAST1":         "asia-northeast1-malachiteingestion-pa.googleapis.com",
	"AUSTRALIA-SOUTHEAST1":    hostAustraliaSoutheast1,
	"SOUTHAMERICA-EAST1":      "southamerica-east1-malachiteingestion-pa.googleapis.com",
	"NORTHAMERICA-NORTHEAST2": "northamerica-northeast2-malachiteingestion-pa.googleapis.com",
}

// endpointFor returns the full ingestion URL for a region, defaulting to the US
// multi-region for empty or unrecognized regions.
func endpointFor(region string) string {
	host := defaultHost
	if h, ok := regionHosts[strings.ToUpper(region)]; ok {
		host = h
	}
	return "https://" + host + endpointPath
}

// Config holds the Chronicle destination settings and the service account
// credentials used to authenticate to it.
type Config struct {
	CustomerID         string
	Region             string
	ServiceAccountJSON []byte
}

// entry is a single Chronicle log entry: the verbatim indicator JSON and its
// event timestamp in epoch microseconds.
type entry struct {
	LogText             string `json:"log_text"`
	TSEpochMicroseconds int64  `json:"ts_epoch_microseconds"`
}

// request is the batchCreate body posted to the ingestion API.
type request struct {
	CustomerID string  `json:"customer_id"`
	LogType    string  `json:"log_type"`
	Entries    []entry `json:"entries"`
}

// Client posts batches of indicators to a Chronicle ingestion endpoint over an
// OAuth2-authorized HTTP client. It is safe for use by a single writer.
type Client struct {
	customerID string
	endpoint   string
	newClient  func() *http.Client
	http       *http.Client
	now        func() time.Time
}

// New builds a Client that authenticates with the given service account JSON
// and targets the ingestion endpoint for the configured region.
func New(ctx context.Context, cfg Config) (*Client, error) {
	creds, err := google.CredentialsFromJSONWithType(ctx, cfg.ServiceAccountJSON, google.ServiceAccount, oauthScopes...)
	if err != nil {
		return nil, fmt.Errorf("chronicle: loading service account credentials: %w", err)
	}

	newClient := authorizedClientFactory(creds.TokenSource)
	c := &Client{
		customerID: cfg.CustomerID,
		endpoint:   endpointFor(cfg.Region),
		newClient:  newClient,
		http:       newClient(),
		now:        time.Now,
	}
	return c, nil
}

// authorizedClientFactory returns a function that builds a fresh HTTP client
// which injects a bearer token from ts and bounds the TCP dial. A factory (not
// a single client) lets ResetSession rebuild the client without a context.
func authorizedClientFactory(ts oauth2.TokenSource) func() *http.Client {
	return func() *http.Client {
		base := &http.Transport{
			DialContext: (&net.Dialer{Timeout: connectTimeout}).DialContext,
		}
		return &http.Client{
			Transport: &oauth2.Transport{Source: ts, Base: base},
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

// Send posts a batch of indicators to Chronicle as CROWDSTRIKE_IOC log entries.
// Each indicator is forwarded verbatim as JSON with an event timestamp derived
// from its published_date or last_updated field. It returns an error on any
// non-2xx response so the caller can retry.
func (c *Client) Send(ctx context.Context, batch []indicator.Indicator) error {
	entries := make([]entry, 0, len(batch))
	for _, ind := range batch {
		text, err := json.Marshal(ind)
		if err != nil {
			return fmt.Errorf("chronicle: encoding indicator: %w", err)
		}
		entries = append(entries, entry{
			LogText:             string(text),
			TSEpochMicroseconds: c.indicatorTS(ind),
		})
	}

	payload, err := json.Marshal(request{
		CustomerID: c.customerID,
		LogType:    logType,
		Entries:    entries,
	})
	if err != nil {
		return fmt.Errorf("chronicle: encoding request: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("chronicle: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	slog.Debug("posting indicators to chronicle",
		"component", "chronicle",
		"endpoint", c.endpoint,
		"count", len(batch),
	)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("chronicle: posting to %s: %w", c.endpoint, err)
	}
	defer drainClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("chronicle: ingestion returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}

	slog.Debug("chronicle accepted batch",
		"component", "chronicle",
		"status", resp.StatusCode,
		"count", len(batch),
	)
	return nil
}

// indicatorTS returns the event timestamp for an indicator in epoch
// microseconds, preferring published_date, then last_updated, and finally the
// current time when neither field carries a usable value.
func (c *Client) indicatorTS(ind indicator.Indicator) int64 {
	for _, field := range []string{"published_date", "last_updated"} {
		if micros, ok := epochMicros(ind[field]); ok {
			return micros
		}
	}
	return c.now().UnixMicro()
}

// epochMicros converts a Falcon Unix-epoch-seconds value into epoch
// microseconds. Indicators are decoded with the standard JSON decoder, so a
// numeric field arrives as a float64 and a numeric string as a string; both are
// handled. A zero, missing, or unparseable value yields ok=false so the caller
// can fall through to the next field.
func epochMicros(v any) (int64, bool) {
	var secs float64
	switch x := v.(type) {
	case float64:
		secs = x
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return 0, false
		}
		secs = f
	default:
		return 0, false
	}
	if secs == 0 {
		return 0, false
	}
	return int64(secs * 1e6), true
}

// drainClose consumes and closes a response body so the connection can be
// reused by the transport's pool.
func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
