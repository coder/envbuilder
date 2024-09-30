package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/coder/envbuilder/options"

	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/log"
	"github.com/coder/serpent"

	// *Never* remove this. Certificates are not bundled as part
	// of the container, so this is necessary for all connections
	// to not be insecure.
	_ "github.com/breml/rootcerts"
)

func main() {
	cmd := envbuilderCmd()
	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
}

func envbuilderCmd() serpent.Command {
	var o options.Options
	cmd := serpent.Command{
		Use:     "envbuilder",
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			o.SetDefaults()
			var preExecs []func()
			preExec := func() {
				for _, fn := range preExecs {
					fn()
				}
				preExecs = nil
			}
			defer preExec() // Ensure cleanup in case of error.

			o.Logger = log.New(os.Stderr, o.Verbose)
			if o.CoderAgentURL != "" {
				if o.CoderAgentToken == "" {
					return errors.New("CODER_AGENT_URL must be set if CODER_AGENT_TOKEN is set")
				}
				u, err := url.Parse(o.CoderAgentURL)
				if err != nil {
					return fmt.Errorf("unable to parse CODER_AGENT_URL as URL: %w", err)
				}
				coderLog, closeLogs, err := log.Coder(inv.Context(), u, o.CoderAgentToken)
				if err == nil {
					o.Logger = log.Wrap(o.Logger, coderLog)
					preExecs = append(preExecs, func() {
						o.Logger(log.LevelInfo, "Closing logs")
						closeLogs()
					})
					// This adds the envbuilder subsystem.
					// If telemetry is enabled in a Coder deployment,
					// this will be reported and help us understand
					// envbuilder usage.
					if !slices.Contains(o.CoderAgentSubsystem, string(codersdk.AgentSubsystemEnvbuilder)) {
						o.CoderAgentSubsystem = append(o.CoderAgentSubsystem, string(codersdk.AgentSubsystemEnvbuilder))
						_ = os.Setenv("CODER_AGENT_SUBSYSTEM", strings.Join(o.CoderAgentSubsystem, ","))
					}
				} else {
					// Failure to log to Coder should cause a fatal error.
					o.Logger(log.LevelError, "unable to send logs to Coder: %s", err.Error())
				}
			}

			if o.GetCachedImage {
				img, err := envbuilder.RunCacheProbe(inv.Context(), o)
				if err != nil {
					o.Logger(log.LevelError, "error: %s", err)
					return err
				}
				digest, err := img.Digest()
				if err != nil {
					return fmt.Errorf("get cached image digest: %w", err)
				}
				_, _ = fmt.Fprintf(inv.Stdout, "ENVBUILDER_CACHED_IMAGE=%s@%s\n", o.CacheRepo, digest.String())
				return nil
			}

			err := envbuilder.Run(inv.Context(), o, preExec)
			if err != nil {
				o.Logger(log.LevelError, "error: %s", err)
			}
			return err
		},
	}
	return cmd
}
