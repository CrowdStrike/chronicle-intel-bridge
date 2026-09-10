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

// Package config resolves CCIB configuration from command-line flags,
// environment variables, and an optional config file, then validates it before
// startup.
//
// Precedence, highest to lowest: command-line flag, environment variable,
// config file (--config, default config/config.yaml), built-in default. An
// unspecified flag or an empty environment variable falls through to the next
// source, preserving the deployment contract of a mountable config file plus
// env overrides.
//
// The config file may be in any format Viper can decode with the codecs
// wired up here: YAML, JSON, TOML, dotenv, or INI. The format is detected
// from the file extension, so config.json, config.toml, and config.ini all
// work in place of the default config.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/go-viper/encoding/ini"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/falcon"
)

// Built-in defaults, declared once and applied to both the pflag defaults and
// the Viper defaults so the two cannot drift.
const (
	defaultLogLevel            = "INFO"
	defaultLogFormat           = "text"
	defaultSyncFrequency       = 60
	defaultInitialSyncLookback = 14400
	defaultFalconCloud         = "autodiscover"
	defaultCacheMaxSize        = 100000
	defaultStateFile           = "data/state.json"
	defaultConfigFile          = "config/config.yaml"
)

// Viper keys, matching the INI section.key layout of the config file.
const (
	keyLogLevel                = "logging.level"
	keyLogFormat               = "logging.format"
	keySyncFrequency           = "indicators.sync_frequency"
	keyInitialSyncLookback     = "indicators.initial_sync_lookback"
	keyFalconCloud             = "falcon.cloud"
	keyFalconClientID          = "falcon.client_id"
	keyFalconClientSecret      = "falcon.client_secret"
	keyChronicleServiceAccount = "chronicle.service_account"
	keyChronicleCustomerID     = "chronicle.customer_id"
	keyChronicleRegion         = "chronicle.region"
	keyCacheMaxSize            = "cache.max_size"
	keyStateFile               = "state.file"
)

// flagConfig selects the config file to load.
const flagConfig = "config"

// validLogFormats is the set of log output formats CCIB accepts, matched
// case-insensitively. Both are slog's built-in handlers: text is the
// human-readable default, json emits one JSON object per line for log
// aggregators.
var validLogFormats = []string{"text", "json"}

// validLogLevels is the set of log levels CCIB accepts, matched
// case-insensitively. They map to slog's built-in levels; an unrecognized value
// would otherwise be silently coerced to info when the handler is built.
var validLogLevels = []string{"debug", "info", "warn", "error"}

// option maps a Viper key to its CLI flag and, where one exists, the
// environment variable that overrides the config file. An empty env means the
// option has no environment override (matching the original behavior for the
// indicators settings).
type option struct {
	key  string
	flag string
	env  string
}

// options is the single source of truth linking keys, flags, and env vars.
var options = []option{
	{keyLogLevel, "log-level", "LOG_LEVEL"},
	{keyLogFormat, "log-format", "LOG_FORMAT"},
	{keySyncFrequency, "sync-frequency", ""},
	{keyInitialSyncLookback, "initial-sync-lookback", ""},
	{keyFalconCloud, "falcon-cloud", "FALCON_CLOUD"},
	{keyFalconClientID, "falcon-client-id", "FALCON_CLIENT_ID"},
	{keyFalconClientSecret, "falcon-client-secret", "FALCON_CLIENT_SECRET"},
	{keyChronicleServiceAccount, "chronicle-service-account", "GOOGLE_SERVICE_ACCOUNT_FILE"},
	{keyChronicleCustomerID, "chronicle-customer-id", "CHRONICLE_CUSTOMER_ID"},
	{keyChronicleRegion, "chronicle-region", "CHRONICLE_REGION"},
	{keyCacheMaxSize, "cache-max-size", "CACHE_MAX_SIZE"},
	{keyStateFile, "state-file", "STATE_FILE"},
}

// Config holds the fully resolved CCIB configuration.
type Config struct {
	LogLevel  string
	LogFormat string

	SyncFrequency       int
	InitialSyncLookback int

	FalconCloud        string
	FalconClientID     string
	FalconClientSecret string

	ChronicleServiceAccount string
	ChronicleCustomerID     string
	ChronicleRegion         string

	CacheMaxSize int
	StateFile    string
}

// BindFlags registers the --config flag and every CCIB option flag on fs, with
// defaults drawn from the shared constants. The root command calls this so the
// flags appear in --help and can be bound by Load.
func BindFlags(fs *pflag.FlagSet) {
	fs.String(flagConfig, defaultConfigFile, "path to the config file")
	fs.String("log-level", defaultLogLevel, "log level: ERROR, WARN, INFO, or DEBUG")
	fs.String("log-format", defaultLogFormat, "log format: text or json")
	fs.Int("sync-frequency", defaultSyncFrequency, "Falcon Intel poll interval in seconds")
	fs.Int("initial-sync-lookback", defaultInitialSyncLookback, "initial sync look-back window in seconds")
	fs.String("falcon-cloud", defaultFalconCloud, "Falcon cloud region")
	fs.String("falcon-client-id", "", "Falcon API OAuth client ID")
	fs.String("falcon-client-secret", "", "Falcon API OAuth client secret")
	fs.String("chronicle-service-account", "", "path to the Google service account JSON file")
	fs.String("chronicle-customer-id", "", "Chronicle customer ID")
	fs.String("chronicle-region", "", "Chronicle region")
	fs.Int("cache-max-size", defaultCacheMaxSize, "maximum number of entries in the dedup cache")
	fs.String("state-file", defaultStateFile, "path to the persisted state file")
}

// Load resolves configuration from fs (which must have been populated by
// BindFlags), environment variables, and the --config file, applying the
// standard flag > env > file > default precedence. A missing config file is
// tolerated; a malformed numeric option is reported as an error.
func Load(fs *pflag.FlagSet) (*Config, error) {
	v, err := newViper()
	if err != nil {
		return nil, err
	}
	setDefaults(v)
	if err := bindEnv(v); err != nil {
		return nil, err
	}
	if err := bindFlags(v, fs); err != nil {
		return nil, err
	}
	if err := readConfigFile(v, fs); err != nil {
		return nil, err
	}

	c := &Config{
		LogLevel:                v.GetString(keyLogLevel),
		LogFormat:               v.GetString(keyLogFormat),
		FalconCloud:             v.GetString(keyFalconCloud),
		FalconClientID:          v.GetString(keyFalconClientID),
		FalconClientSecret:      v.GetString(keyFalconClientSecret),
		ChronicleServiceAccount: v.GetString(keyChronicleServiceAccount),
		ChronicleCustomerID:     v.GetString(keyChronicleCustomerID),
		ChronicleRegion:         v.GetString(keyChronicleRegion),
		StateFile:               v.GetString(keyStateFile),
	}

	// Integer options are read as strings and parsed explicitly so a
	// non-numeric value fails fast with a clear message; Viper's GetInt would
	// silently coerce a malformed value to 0.
	if c.SyncFrequency, err = parseInt("sync frequency", v.GetString(keySyncFrequency)); err != nil {
		return nil, err
	}
	if c.InitialSyncLookback, err = parseInt("initial sync lookback", v.GetString(keyInitialSyncLookback)); err != nil {
		return nil, err
	}
	if c.CacheMaxSize, err = parseInt("cache max size", v.GetString(keyCacheMaxSize)); err != nil {
		return nil, err
	}

	return c, nil
}

// newViper returns a Viper instance whose INI codec is registered. JSON, YAML,
// TOML, and dotenv are handled by Viper's built-in codecs; registering INI here
// rounds out the set of config file formats CCIB accepts.
func newViper() (*viper.Viper, error) {
	registry := viper.NewCodecRegistry()
	if err := registry.RegisterCodec("ini", ini.Codec{}); err != nil {
		return nil, fmt.Errorf("config: registering INI codec: %w", err)
	}
	return viper.NewWithOptions(viper.WithCodecRegistry(registry)), nil
}

// setDefaults seeds Viper with the built-in defaults.
func setDefaults(v *viper.Viper) {
	v.SetDefault(keyLogLevel, defaultLogLevel)
	v.SetDefault(keyLogFormat, defaultLogFormat)
	v.SetDefault(keySyncFrequency, defaultSyncFrequency)
	v.SetDefault(keyInitialSyncLookback, defaultInitialSyncLookback)
	v.SetDefault(keyFalconCloud, defaultFalconCloud)
	v.SetDefault(keyFalconClientID, "")
	v.SetDefault(keyFalconClientSecret, "")
	v.SetDefault(keyChronicleServiceAccount, "")
	v.SetDefault(keyChronicleCustomerID, "")
	v.SetDefault(keyChronicleRegion, "")
	v.SetDefault(keyCacheMaxSize, defaultCacheMaxSize)
	v.SetDefault(keyStateFile, defaultStateFile)
}

// bindEnv binds each option's explicit environment variable. Names are
// non-uniform, so they are bound individually rather than via a prefix. With
// AllowEmptyEnv left at its default of false, an empty env var is treated as
// unset and does not override the config file or default.
func bindEnv(v *viper.Viper) error {
	for _, o := range options {
		if o.env == "" {
			continue
		}
		if err := v.BindEnv(o.key, o.env); err != nil {
			return fmt.Errorf("config: binding env %s: %w", o.env, err)
		}
	}
	return nil
}

// bindFlags binds each option's flag from fs. A bound flag takes effect only
// when the user set it, so unspecified flags fall through to env, file, or
// default.
func bindFlags(v *viper.Viper, fs *pflag.FlagSet) error {
	for _, o := range options {
		flag := fs.Lookup(o.flag)
		if flag == nil {
			return fmt.Errorf("config: flag --%s not registered; call BindFlags first", o.flag)
		}
		if err := v.BindPFlag(o.key, flag); err != nil {
			return fmt.Errorf("config: binding flag --%s: %w", o.flag, err)
		}
	}
	return nil
}

// readConfigFile loads the --config file into v, tolerating a missing file.
// Viper infers the format from the file extension (json, yaml, toml, env, ini,
// ...); an extensionless path is read as INI to preserve the historical
// default.
func readConfigFile(v *viper.Viper, fs *pflag.FlagSet) error {
	path, err := fs.GetString(flagConfig)
	if err != nil {
		return fmt.Errorf("config: reading --%s flag: %w", flagConfig, err)
	}
	if path == "" {
		return nil
	}
	v.SetConfigFile(path)
	if filepath.Ext(path) == "" {
		v.SetConfigType("ini")
	}
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("config: reading config file %q: %w", path, err)
	}
	return nil
}

// Validate reports the first configuration error found, or nil when the
// configuration is usable.
func (c *Config) Validate() error {
	if c.SyncFrequency < 1 || c.SyncFrequency > 3599 {
		return fmt.Errorf("malformed configuration: sync frequency must be between 1 and 3599 seconds, got %d", c.SyncFrequency)
	}
	if c.InitialSyncLookback < 60 || c.InitialSyncLookback > 7775999 {
		return fmt.Errorf("malformed configuration: initial sync lookback must be between 60 and 7775999 seconds, got %d", c.InitialSyncLookback)
	}
	if err := falcon.ValidateCloud(c.FalconCloud); err != nil {
		return err
	}
	if !slices.Contains(validLogFormats, strings.ToLower(c.LogFormat)) {
		return fmt.Errorf("malformed configuration: log format must be text or json, got %q", c.LogFormat)
	}
	if !slices.Contains(validLogLevels, strings.ToLower(c.LogLevel)) {
		return fmt.Errorf("malformed configuration: log level must be one of debug, info, warn, error, got %q", c.LogLevel)
	}
	if c.FalconClientID == "" {
		return errors.New("missing configuration: Falcon Client ID is required")
	}
	if c.FalconClientSecret == "" {
		return errors.New("missing configuration: Falcon Client Secret is required")
	}
	if c.ChronicleServiceAccount == "" {
		return errors.New("missing configuration: Chronicle Service Account file is required")
	}
	if c.ChronicleCustomerID == "" {
		return errors.New("missing configuration: Chronicle Customer ID is required")
	}
	return nil
}

// parseInt converts an INI/env/flag integer option, attributing any error to
// the named option for a clear diagnostic.
func parseInt(name, value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("malformed configuration: %s must be an integer, got %q", name, value)
	}
	return n, nil
}
