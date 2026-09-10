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

// Package falcon fetches CrowdStrike Falcon intelligence indicators, paginating
// by the API's _marker cursor and normalizing each typed SDK resource into an
// open indicator map for lossless forwarding to Chronicle.
package falcon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/version"
)

// pageLimit is the maximum number of indicators requested per page. A full page
// signals that more indicators remain and pagination should continue.
const pageLimit = 1000

// fetchRetryDelay is the pause between attempts when a page fetch fails. Fetches
// retry indefinitely so a transient API outage never ends the daemon.
const fetchRetryDelay = 5 * time.Second

// userAgent identifies CCIB to the Falcon API.
var userAgent = "chronicle-intel-bridge/" + version.Version

// indicatorQuerier is the slice of the gofalcon intel client CCIB depends on,
// narrowed to the single call it makes so tests can supply a fake.
type indicatorQuerier interface {
	QueryIntelIndicatorEntities(params *intel.QueryIntelIndicatorEntitiesParams, opts ...intel.ClientOption) (*intel.QueryIntelIndicatorEntitiesOK, error)
}

// Config holds the credentials and region needed to reach the Falcon Intel API.
type Config struct {
	ClientID     string
	ClientSecret string
	CloudRegion  string
}

// Client reads intelligence indicators from the Falcon Intel API.
type Client struct {
	intel      indicatorQuerier
	retryDelay time.Duration
}

// New builds a Client authenticated with the given credentials against the
// configured cloud region. An unrecognized region falls back to US-1, matching
// the SDK's own default.
func New(ctx context.Context, cfg Config) (*Client, error) {
	api, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:          cfg.ClientID,
		ClientSecret:      cfg.ClientSecret,
		Cloud:             falcon.Cloud(cfg.CloudRegion),
		Context:           ctx,
		UserAgentOverride: userAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("falcon: creating client: %w", err)
	}
	return &Client{intel: api.Intel, retryDelay: fetchRetryDelay}, nil
}

// ValidateCloud reports whether region names a CrowdStrike cloud the
// Falcon SDK recognizes, so misconfiguration fails fast at startup rather than
// silently falling back to US-1 when New builds the client. Matching the SDK's
// own parsing, an empty region is accepted and resolves to autodiscovery.
func ValidateCloud(region string) error {
	if _, err := falcon.CloudValidate(region); err != nil {
		return fmt.Errorf("falcon: %w", err)
	}
	return nil
}

// Cursor identifies where the next fetch should resume. It resumes either after
// a previously persisted _marker or, on a first run, from a unix-second
// timestamp representing the initial lookback.
type Cursor struct {
	marker string
	since  int64
}

// FromMarker returns a Cursor that resumes immediately after a saved _marker.
func FromMarker(marker string) Cursor {
	return Cursor{marker: marker}
}

// FromTime returns a Cursor that starts from the given unix-second timestamp,
// used for the initial lookback before any marker has been persisted.
func FromTime(since int64) Cursor {
	return Cursor{since: since}
}

// filter builds the FQL selecting undeleted indicators at or after the cursor
// position. A marker cursor filters on _marker; a fresh cursor filters on
// last_updated.
func (c Cursor) filter() string {
	if c.marker != "" {
		return fmt.Sprintf("_marker:>='%s'+deleted:false", c.marker)
	}
	return fmt.Sprintf("last_updated:>=%d+deleted:false", c.since)
}

// Stream fetches successive pages of indicators starting at cur and invokes fn
// for each non-empty page together with the _marker of that page's last
// indicator. It stops after a partial page or an empty trailing marker, which
// both mean no further indicators are available. An error from fn aborts the
// stream. Stream honors ctx cancellation between and during fetches.
func (c *Client) Stream(ctx context.Context, cur Cursor, fn func(page []indicator.Indicator, lastMarker string) error) error {
	var fetched int64
	for {
		payload, err := c.fetch(ctx, cur)
		if err != nil {
			return err
		}
		resources := payload.Resources
		if len(resources) == 0 {
			return nil
		}

		page, err := normalize(resources)
		if err != nil {
			return err
		}
		marker := lastMarker(resources)

		fetched += int64(len(resources))
		slog.Info("fetched indicator page",
			"component", "falcon",
			"page", len(resources),
			"fetched", fetched,
			"total", paginationTotal(payload),
		)
		slog.Debug("advancing marker cursor", "component", "falcon", "marker", marker)

		if err := fn(page, marker); err != nil {
			return err
		}

		if len(resources) < pageLimit || marker == "" {
			return nil
		}
		cur = FromMarker(marker)
	}
}

// fetch requests a single page of indicators for cur, retrying every
// retryDelay until it succeeds or ctx is cancelled. It returns an error only
// when ctx is cancelled, so callers need not implement their own retry.
func (c *Client) fetch(ctx context.Context, cur Cursor) (*models.DomainPublicIndicatorsV3Response, error) {
	filter := cur.filter()
	sort := "_marker.asc"
	limit := int64(pageLimit)
	includeDeleted := false

	slog.Debug("querying falcon indicators", "component", "falcon", "filter", filter, "sort", sort)

	for {
		params := intel.NewQueryIntelIndicatorEntitiesParamsWithContext(ctx)
		params.Filter = &filter
		params.Sort = &sort
		params.Limit = &limit
		params.IncludeDeleted = &includeDeleted

		resp, err := c.intel.QueryIntelIndicatorEntities(params)
		switch {
		case err != nil:
			// transport or API-status error
		case resp == nil || resp.Payload == nil:
			err = errors.New("falcon: empty response payload")
		case len(resp.Payload.Errors) > 0:
			err = payloadError(resp.Payload.Errors)
		default:
			return resp.Payload, nil
		}

		slog.Error("falcon indicator query failed; retrying", "filter", filter, "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.retryDelay):
		}
	}
}

// normalize converts the typed SDK resources into open indicator maps via a
// single JSON round trip, preserving every field the SDK models (including
// _marker, labels, and relations).
func normalize(resources []*models.DomainPublicIndicatorV3) ([]indicator.Indicator, error) {
	out := make([]indicator.Indicator, 0, len(resources))
	for _, r := range resources {
		if r == nil {
			continue
		}
		raw, err := r.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("falcon: marshaling indicator: %w", err)
		}
		var m indicator.Indicator
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("falcon: decoding indicator: %w", err)
		}
		out = append(out, m)
	}
	return out, nil
}

// lastMarker returns the _marker of the final resource, or the empty string
// when the page is empty or that marker is absent.
func lastMarker(resources []*models.DomainPublicIndicatorV3) string {
	if len(resources) == 0 {
		return ""
	}
	last := resources[len(resources)-1]
	if last == nil || last.Marker == nil {
		return ""
	}
	return *last.Marker
}

// paginationTotal returns the total number of matching indicators the API
// reports for the query, or 0 when the response carries no pagination metadata.
// It lets the initial backfill log progress against a known total.
func paginationTotal(payload *models.DomainPublicIndicatorsV3Response) int64 {
	if payload == nil || payload.Meta == nil || payload.Meta.Pagination == nil || payload.Meta.Pagination.Total == nil {
		return 0
	}
	return *payload.Meta.Pagination.Total
}

// payloadError flattens the API's structured errors into a single error value.
func payloadError(errs []*models.MsaAPIError) error {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		if e != nil && e.Message != nil {
			msgs = append(msgs, *e.Message)
		}
	}
	return fmt.Errorf("falcon: api errors: %s", strings.Join(msgs, "; "))
}
