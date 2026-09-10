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

// Package cli builds the ccib command-line interface: a single root command
// that resolves configuration, then runs the reader/writer daemon until it is
// interrupted.
package cli

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/config"
	"github.com/crowdstrike/chronicle-intel-bridge/internal/version"
)

// Execute runs the ccib root command. It returns a non-nil error only on a
// fatal failure; a signalled shutdown yields nil.
func Execute() error {
	return NewRootCommand().ExecuteContext(context.Background())
}

// NewRootCommand builds the root ccib command with all configuration flags
// bound.
func NewRootCommand() *cobra.Command {
	var cfg *config.Config

	cmd := &cobra.Command{
		Use:     "ccib",
		Short:   "Forward CrowdStrike Falcon intelligence indicators to Google Chronicle",
		Version: version.Version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			cfg, err = config.Load(cmd.Flags())
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return err
			}

			setupLogging(cfg.LogLevel, cfg.LogFormat)

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true

			slog.Info("starting ccib", "version", version.Version, "commit", version.Commit)
			return runDaemon(cmd.Context(), cfg)
		},
	}
	config.BindFlags(cmd.Flags())
	cmd.SetVersionTemplate("ccib {{.Version}} <commit " + version.Commit + ">\n")
	return cmd
}
