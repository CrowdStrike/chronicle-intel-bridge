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

package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/chronicle"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/config"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/dedup"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/falcon"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/pipeline"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/state"
)

// shutdownGrace bounds how long runDaemon waits for the writer to drain buffered
// batches after a shutdown signal. An in-flight Chronicle send is detached from
// the signal and can run for the full request timeout, and up to QueueSize
// batches may be buffered, so a full drain can outlast an orchestrator's
// termination grace period and be SIGKILLed mid-drain. This deadline is a bound,
// not a guarantee: it should sit below the deployment's grace period. Exiting
// early is safe because state writes are atomic, so at worst the last in-flight
// marker save is lost and its window is re-fetched on the next start.
const shutdownGrace = 25 * time.Second

// runDaemon wires the reader and writer from cfg and blocks until both
// goroutines return. It cancels ctx on SIGINT or SIGTERM so the daemon shuts
// down gracefully; a clean shutdown (context cancelled by a signal) yields a
// nil error. After a signal it waits at most shutdownGrace for the writer to
// drain before exiting so the process does not outlive its termination grace
// period.
func runDaemon(ctx context.Context, cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	reader, writer, err := build(ctx, cfg)
	if err != nil {
		return err
	}

	batches := make(chan pipeline.Batch, pipeline.QueueSize)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return reader.Run(gctx, batches) })
	g.Go(func() error { return writer.Run(gctx, batches) })

	done := make(chan error, 1)
	go func() { done <- g.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		select {
		case err := <-done:
			if err != nil {
				return err
			}
		case <-time.After(shutdownGrace):
			slog.Warn("shutdown grace period elapsed; exiting with delivery still draining",
				"component", "daemon",
				"grace", shutdownGrace,
			)
			return nil
		}
	}
	slog.Info("ccib shut down cleanly")
	return nil
}

// build constructs the reader and writer and their collaborators from cfg.
func build(ctx context.Context, cfg *config.Config) (*pipeline.Reader, *pipeline.Writer, error) {
	slog.Info("initializing ccib",
		"component", "daemon",
		"falcon_cloud", cfg.FalconCloud,
		"chronicle_region", cfg.ChronicleRegion,
		"chronicle_customer_id", cfg.ChronicleCustomerID,
	)

	source, err := falcon.New(ctx, falcon.Config{
		ClientID:     cfg.FalconClientID,
		ClientSecret: cfg.FalconClientSecret,
		CloudRegion:  cfg.FalconCloud,
	})
	if err != nil {
		return nil, nil, err
	}

	saJSON, err := os.ReadFile(cfg.ChronicleServiceAccount)
	if err != nil {
		return nil, nil, fmt.Errorf("reading service account file %q: %w", cfg.ChronicleServiceAccount, err)
	}
	sink, err := chronicle.New(ctx, chronicle.Config{
		CustomerID:         cfg.ChronicleCustomerID,
		Region:             cfg.ChronicleRegion,
		ServiceAccountJSON: saJSON,
	})
	if err != nil {
		return nil, nil, err
	}

	cache, err := dedup.New(cfg.CacheMaxSize)
	if err != nil {
		return nil, nil, fmt.Errorf("creating dedup cache: %w", err)
	}

	store := state.New(cfg.StateFile)

	reader := pipeline.NewReader(pipeline.ReaderConfig{
		Source:    source,
		Cache:     cache,
		Frequency: time.Duration(cfg.SyncFrequency) * time.Second,
		Start:     startCursor(store, cfg.InitialSyncLookback),
	})
	writer := pipeline.NewWriter(pipeline.WriterConfig{
		Sink:  sink,
		State: store,
		Dedup: cache,
	})
	return reader, writer, nil
}

// startCursor resumes from the last persisted marker when one exists, otherwise
// it starts from the initial lookback window before now. A corrupt or unreadable
// state file is logged and treated as no marker, falling back to the lookback
// window rather than aborting startup.
func startCursor(store *state.Store, lookbackSeconds int) falcon.Cursor {
	marker, err := store.Load()
	if err != nil {
		slog.Warn("could not read saved marker; starting from initial lookback", "error", err)
	} else if marker != "" {
		slog.Info("resuming from saved marker", "marker", marker)
		return falcon.FromMarker(marker)
	}
	since := time.Now().Add(-time.Duration(lookbackSeconds) * time.Second).Unix()
	slog.Info("no saved marker; starting from initial lookback", "lookback_seconds", lookbackSeconds)
	return falcon.FromTime(since)
}

// setupLogging installs a slog handler on stderr at the configured level and
// format and makes it the default logger. It also raises the level at which the
// standard log package's output is bridged into slog to ERROR: main's log.Fatal
// writes through that bridge, and at LOG_LEVEL=ERROR an INFO-level bridge would
// be dropped, silently swallowing a fatal startup error. Emitting it at ERROR
// keeps it visible and routes it through the configured handler's destination
// and format rather than assuming stderr.
func setupLogging(level, format string) {
	slog.SetLogLoggerLevel(slog.LevelError)
	slog.SetDefault(slog.New(newLogHandler(logHandlerOptions{Writer: os.Stderr, Level: level, Format: format})))
}

// logHandlerOptions configures newLogHandler.
type logHandlerOptions struct {
	Writer io.Writer
	Level  string
	Format string
}

// newLogHandler builds a slog handler from opts. An empty or unrecognized level
// defaults to info; an unrecognized format defaults to text (format is validated
// at startup, so this fallback is a safety net).
func newLogHandler(opts logHandlerOptions) slog.Handler {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(opts.Level)); err != nil {
		lvl = slog.LevelInfo
	}
	handlerOpts := &slog.HandlerOptions{Level: lvl}
	if strings.ToLower(opts.Format) == "json" {
		return slog.NewJSONHandler(opts.Writer, handlerOpts)
	}
	return slog.NewTextHandler(opts.Writer, handlerOpts)
}
