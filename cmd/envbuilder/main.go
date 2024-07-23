package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/internal/log"
	"github.com/coder/envbuilder/pkg/options"

	"github.com/coder/coder/v2/codersdk"
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
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
}

func envbuilderCmd() serpent.Command {
	var options options.Options
	cmd := serpent.Command{
		Use:     "envbuilder",
		Options: options.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			options.Logger = log.New(os.Stderr, options.Verbose)
			if options.CoderAgentURL != "" {
				if options.CoderAgentToken == "" {
					return errors.New("CODER_AGENT_URL must be set if CODER_AGENT_TOKEN is set")
				}
				u, err := url.Parse(options.CoderAgentURL)
				if err != nil {
					return fmt.Errorf("unable to parse CODER_AGENT_URL as URL: %w", err)
				}
				coderLog, closeLogs, err := log.Coder(inv.Context(), u, options.CoderAgentToken)
				if err == nil {
					options.Logger = log.Wrap(options.Logger, coderLog)
					defer closeLogs()
					// This adds the envbuilder subsystem.
					// If telemetry is enabled in a Coder deployment,
					// this will be reported and help us understand
					// envbuilder usage.
					if !slices.Contains(options.CoderAgentSubsystem, string(codersdk.AgentSubsystemEnvbuilder)) {
						options.CoderAgentSubsystem = append(options.CoderAgentSubsystem, string(codersdk.AgentSubsystemEnvbuilder))
						_ = os.Setenv("CODER_AGENT_SUBSYSTEM", strings.Join(options.CoderAgentSubsystem, ","))
					}
				} else {
					// Failure to log to Coder should cause a fatal error.
					options.Logger(log.LevelError, "unable to send logs to Coder: %s", err.Error())
				}
			}

			err := envbuilder.Run(inv.Context(), options)
			if err != nil {
				options.Logger(log.LevelError, "error: %s", err)
			}
			return err
		},
	}
	return cmd
}
