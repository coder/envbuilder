package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"cdr.dev/slog"
	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/internal/notcodersdk"
	"github.com/coder/serpent"

	// *Never* remove this. Certificates are not bundled as part
	// of the container, so this is necessary for all connections
	// to not be insecure.
	_ "github.com/breml/rootcerts"
)

func main() {
	var options envbuilder.Options
	cmd := serpent.Command{
		Use:     "envbuilder",
		Options: options.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			var sendLogs func(ctx context.Context, log ...notcodersdk.Log) error
			if options.CoderAgentToken != "" {
				if options.CoderAgentURL == "" {
					return errors.New("CODER_AGENT_URL must be set if CODER_AGENT_TOKEN is set")
				}
				u, err := url.Parse(options.CoderAgentURL)
				if err != nil {
					return fmt.Errorf("unable to parse CODER_AGENT_URL as URL: %w", err)
				}
				client := notcodersdk.New(u)
				client.SetSessionToken(options.CoderAgentToken)
				client.HTTPClient = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: options.Insecure,
						},
					},
				}
				var flushAndClose func(ctx context.Context) error
				sendLogs, flushAndClose = notcodersdk.LogsSender(notcodersdk.ExternalLogSourceID, client.PatchLogs, slog.Logger{})
				defer flushAndClose(inv.Context())

				// This adds the envbuilder subsystem.
				// If telemetry is enabled in a Coder deployment,
				// this will be reported and help us understand
				// envbuilder usage.
				if !slices.Contains(options.CoderAgentSubsystem, string(notcodersdk.AgentSubsystemEnvbuilder)) {
					options.CoderAgentSubsystem = append(options.CoderAgentSubsystem, string(notcodersdk.AgentSubsystemEnvbuilder))
					os.Setenv("CODER_AGENT_SUBSYSTEM", strings.Join(options.CoderAgentSubsystem, ","))
				}
			}

			options.Logger = func(level notcodersdk.LogLevel, format string, args ...interface{}) {
				output := fmt.Sprintf(format, args...)
				fmt.Fprintln(inv.Stderr, output)
				if sendLogs != nil {
					sendLogs(inv.Context(), notcodersdk.Log{
						CreatedAt: time.Now(),
						Output:    output,
						Level:     level,
					})
				}
			}

			err := envbuilder.Run(inv.Context(), options)
			if err != nil {
				options.Logger(notcodersdk.LogLevelError, "error: %s", err)
			}
			return err
		},
	}
	err := cmd.Invoke().WithOS().Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
}
