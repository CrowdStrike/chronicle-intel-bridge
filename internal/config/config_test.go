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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
)

// writeINI creates a config.ini file with the given content and returns its path.
func writeINI(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config.ini: %v", err)
	}
	return path
}

// newFlagSet returns a flag set populated with all CCIB flags, as the root
// command builds it.
func newFlagSet(t *testing.T) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	BindFlags(fs)
	return fs
}

// setFlag sets a flag on fs and fails the test if the flag is unknown.
func setFlag(t *testing.T, fs *pflag.FlagSet, name, value string) {
	t.Helper()
	if err := fs.Set(name, value); err != nil {
		t.Fatalf("setting --%s: %v", name, err)
	}
}

func TestLoadDefaults(t *testing.T) {
	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, filepath.Join(t.TempDir(), "absent.ini"))

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.LogLevel != defaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", c.LogLevel, defaultLogLevel)
	}
	if c.LogFormat != defaultLogFormat {
		t.Errorf("LogFormat = %q, want %q", c.LogFormat, defaultLogFormat)
	}
	if c.SyncFrequency != defaultSyncFrequency {
		t.Errorf("SyncFrequency = %d, want %d", c.SyncFrequency, defaultSyncFrequency)
	}
	if c.InitialSyncLookback != defaultInitialSyncLookback {
		t.Errorf("InitialSyncLookback = %d, want %d", c.InitialSyncLookback, defaultInitialSyncLookback)
	}
	if c.FalconCloud != defaultFalconCloud {
		t.Errorf("FalconCloud = %q, want %q", c.FalconCloud, defaultFalconCloud)
	}
	if c.CacheMaxSize != defaultCacheMaxSize {
		t.Errorf("CacheMaxSize = %d, want %d", c.CacheMaxSize, defaultCacheMaxSize)
	}
	if c.StateFile != defaultStateFile {
		t.Errorf("StateFile = %q, want %q", c.StateFile, defaultStateFile)
	}
}

func TestLoadConfigFileValue(t *testing.T) {
	// Neutralize any real FALCON_CLIENT_ID / CACHE_MAX_SIZE in the environment
	// so the config-file values under test are what actually resolve.
	t.Setenv("FALCON_CLIENT_ID", "")
	t.Setenv("CACHE_MAX_SIZE", "")

	dir := t.TempDir()
	cfg := writeINI(t, dir, "[falcon]\nclient_id = iniid\n\n[cache]\nmax_size = 500\n")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, cfg)

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.FalconClientID != "iniid" {
		t.Errorf("FalconClientID = %q, want iniid (from config file)", c.FalconClientID)
	}
	if c.CacheMaxSize != 500 {
		t.Errorf("CacheMaxSize = %d, want 500 (from config file)", c.CacheMaxSize)
	}
}

// TestLoadConfigFileFormats verifies that the config file format is detected
// from the file extension, so any Viper-supported format works in place of INI.
func TestLoadConfigFileFormats(t *testing.T) {
	// Neutralize any real FALCON_CLIENT_ID / CACHE_MAX_SIZE in the environment
	// so the config-file values under test are what actually resolve.
	t.Setenv("FALCON_CLIENT_ID", "")
	t.Setenv("CACHE_MAX_SIZE", "")

	tests := []struct {
		name    string
		file    string
		content string
	}{
		{
			name:    "yaml",
			file:    "config.yaml",
			content: "falcon:\n  client_id: fileid\ncache:\n  max_size: 500\n",
		},
		{
			name:    "json",
			file:    "config.json",
			content: `{"falcon":{"client_id":"fileid"},"cache":{"max_size":500}}`,
		},
		{
			name:    "toml",
			file:    "config.toml",
			content: "[falcon]\nclient_id = \"fileid\"\n[cache]\nmax_size = 500\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.file)
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("writing %s: %v", tt.file, err)
			}

			fs := newFlagSet(t)
			setFlag(t, fs, flagConfig, path)

			c, err := Load(fs)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.FalconClientID != "fileid" {
				t.Errorf("FalconClientID = %q, want fileid (from %s config)", c.FalconClientID, tt.name)
			}
			if c.CacheMaxSize != 500 {
				t.Errorf("CacheMaxSize = %d, want 500 (from %s config)", c.CacheMaxSize, tt.name)
			}
		})
	}
}

func TestLoadEnvOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := writeINI(t, dir, "[falcon]\nclient_id = iniid\n")
	t.Setenv("FALCON_CLIENT_ID", "envid")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, cfg)

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.FalconClientID != "envid" {
		t.Errorf("FalconClientID = %q, want envid (env over config)", c.FalconClientID)
	}
}

func TestLoadFlagOverridesEnvAndConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := writeINI(t, dir, "[falcon]\nclient_id = iniid\n")
	t.Setenv("FALCON_CLIENT_ID", "envid")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, cfg)
	setFlag(t, fs, "falcon-client-id", "flagid")

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.FalconClientID != "flagid" {
		t.Errorf("FalconClientID = %q, want flagid (flag over env and config)", c.FalconClientID)
	}
}

func TestLoadEmptyEnvDoesNotOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := writeINI(t, dir, "[falcon]\nclient_id = iniid\n")
	t.Setenv("FALCON_CLIENT_ID", "")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, cfg)

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.FalconClientID != "iniid" {
		t.Errorf("FalconClientID = %q, want iniid (empty env must not override)", c.FalconClientID)
	}
}

// TestLoadNonUniformEnvMapping guards the explicit BindEnv wiring: an env var
// whose name does not match its key still resolves to the right field.
func TestLoadNonUniformEnvMapping(t *testing.T) {
	t.Setenv("GOOGLE_SERVICE_ACCOUNT_FILE", "/secrets/sa.json")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, filepath.Join(t.TempDir(), "absent.ini"))

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ChronicleServiceAccount != "/secrets/sa.json" {
		t.Errorf("ChronicleServiceAccount = %q, want /secrets/sa.json", c.ChronicleServiceAccount)
	}
}

func TestLoadCacheMaxSizeEnv(t *testing.T) {
	t.Setenv("CACHE_MAX_SIZE", "42")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, filepath.Join(t.TempDir(), "absent.ini"))

	c, err := Load(fs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CacheMaxSize != 42 {
		t.Errorf("CacheMaxSize = %d, want 42 (from env)", c.CacheMaxSize)
	}
}

func TestLoadMissingConfigTolerated(t *testing.T) {
	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, filepath.Join(t.TempDir(), "does-not-exist.ini"))

	if _, err := Load(fs); err != nil {
		t.Fatalf("Load with missing config file: %v", err)
	}
}

func TestLoadMalformedNumeric(t *testing.T) {
	dir := t.TempDir()
	bad := writeINI(t, dir, "[indicators]\nsync_frequency = notanumber\n")

	fs := newFlagSet(t)
	setFlag(t, fs, flagConfig, bad)

	if _, err := Load(fs); err == nil {
		t.Fatal("expected error for non-integer sync_frequency, got nil")
	}
}

func baseConfig() *Config {
	return &Config{
		LogLevel:                "INFO",
		LogFormat:               "text",
		SyncFrequency:           60,
		InitialSyncLookback:     14400,
		FalconCloud:             "us-1",
		FalconClientID:          "id",
		FalconClientSecret:      "secret",
		ChronicleServiceAccount: "/secrets/sa.json",
		ChronicleCustomerID:     "cust",
		CacheMaxSize:            100,
		StateFile:               "data/state.json",
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(*Config) {}, false},
		{"sync_frequency low bound ok", func(c *Config) { c.SyncFrequency = 1 }, false},
		{"sync_frequency high bound ok", func(c *Config) { c.SyncFrequency = 3599 }, false},
		{"sync_frequency zero", func(c *Config) { c.SyncFrequency = 0 }, true},
		{"sync_frequency too high", func(c *Config) { c.SyncFrequency = 3600 }, true},
		{"lookback low bound ok", func(c *Config) { c.InitialSyncLookback = 60 }, false},
		{"lookback high bound ok", func(c *Config) { c.InitialSyncLookback = 7775999 }, false},
		{"lookback too low", func(c *Config) { c.InitialSyncLookback = 59 }, true},
		{"lookback too high", func(c *Config) { c.InitialSyncLookback = 7776000 }, true},
		{"bad region", func(c *Config) { c.FalconCloud = "mars-1" }, true},
		{"region us-gov-1 ok", func(c *Config) { c.FalconCloud = "us-gov-1" }, false},
		{"region empty autodiscovers", func(c *Config) { c.FalconCloud = "" }, false},
		{"log format json ok", func(c *Config) { c.LogFormat = "json" }, false},
		{"log format uppercase ok", func(c *Config) { c.LogFormat = "JSON" }, false},
		{"bad log format", func(c *Config) { c.LogFormat = "xml" }, true},
		{"log level debug ok", func(c *Config) { c.LogLevel = "debug" }, false},
		{"log level uppercase ok", func(c *Config) { c.LogLevel = "WARN" }, false},
		{"bad log level", func(c *Config) { c.LogLevel = "verbose" }, true},
		{"empty log level", func(c *Config) { c.LogLevel = "" }, true},
		{"missing client_id", func(c *Config) { c.FalconClientID = "" }, true},
		{"missing client_secret", func(c *Config) { c.FalconClientSecret = "" }, true},
		{"missing service_account", func(c *Config) { c.ChronicleServiceAccount = "" }, true},
		{"missing customer_id", func(c *Config) { c.ChronicleCustomerID = "" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseConfig()
			tt.mutate(c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
