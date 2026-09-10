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
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/falcon"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/state"
)

func TestNewLogHandlerFormat(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		wantJSON   bool
		wantSubstr string
	}{
		{"text", "text", false, "msg=hello"},
		{"json", "json", true, ""},
		{"json uppercase", "JSON", true, ""},
		{"unrecognized falls back to text", "xml", false, "msg=hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(newLogHandler(logHandlerOptions{Writer: &buf, Level: "INFO", Format: tt.format}))
			logger.Info("hello")

			out := buf.String()
			if tt.wantJSON {
				if !json.Valid(bytes.TrimSpace(buf.Bytes())) {
					t.Errorf("expected JSON output, got %q", out)
				}
				return
			}
			if !strings.Contains(out, tt.wantSubstr) {
				t.Errorf("expected text output containing %q, got %q", tt.wantSubstr, out)
			}
		})
	}
}

func TestNewLogHandlerLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(newLogHandler(logHandlerOptions{Writer: &buf, Level: "ERROR", Format: "text"}))
	logger.Info("suppressed")
	if buf.Len() != 0 {
		t.Errorf("info message should be suppressed at ERROR level, got %q", buf.String())
	}
	logger.Error("shown")
	if !strings.Contains(buf.String(), "msg=shown") {
		t.Errorf("error message should be logged at ERROR level, got %q", buf.String())
	}
}

// TestSetupLoggingBridgesStdlibLogAtError guards the fix that keeps log.Fatal
// visible. slog.SetDefault reroutes the standard log package through the slog
// handler, which by default emits those records at INFO and so drops them at
// LOG_LEVEL=ERROR. setupLogging must raise the bridge level to ERROR so a fatal
// startup error survives an ERROR-level handler.
func TestSetupLoggingBridgesStdlibLogAtError(t *testing.T) {
	prevSlog := slog.Default()
	// There is no getter for the bridge level; SetLogLoggerLevel returns the
	// prior value, so read-and-restore it around the assertion.
	origBridge := slog.SetLogLoggerLevel(slog.LevelInfo)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		slog.SetLogLoggerLevel(origBridge)
	})

	setupLogging("ERROR", "text")

	if got := slog.SetLogLoggerLevel(slog.LevelError); got != slog.LevelError {
		t.Errorf("setupLogging should raise the stdlib log bridge level to ERROR so log.Fatal survives an ERROR-level handler, got %v", got)
	}
}

// captureDefaultLogs redirects the default slog logger to a buffer for the
// duration of the test so log assertions are hermetic.
func captureDefaultLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := slog.Default()
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestStartCursorResumesFromMarker(t *testing.T) {
	captureDefaultLogs(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"last_marker":"marker-123"}`), 0o600); err != nil {
		t.Fatalf("seeding state: %v", err)
	}
	if got := startCursor(state.New(path), 3600); got != falcon.FromMarker("marker-123") {
		t.Error("startCursor should resume from the saved marker")
	}
}

func TestStartCursorFallsBackWhenMissing(t *testing.T) {
	captureDefaultLogs(t)
	got := startCursor(state.New(filepath.Join(t.TempDir(), "absent.json")), 3600)
	if got == falcon.FromMarker("marker-123") {
		t.Error("startCursor should fall back to the lookback window when no marker is saved")
	}
}

func TestStartCursorWarnsOnCorrupt(t *testing.T) {
	buf := captureDefaultLogs(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seeding corrupt state: %v", err)
	}
	got := startCursor(state.New(path), 3600)
	if got == falcon.FromMarker("marker-123") {
		t.Error("startCursor should not resume from a corrupt marker file")
	}
	if !strings.Contains(buf.String(), "could not read saved marker") {
		t.Errorf("expected a warning about the corrupt marker file, got %q", buf.String())
	}
}
