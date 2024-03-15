package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"cdr.dev/slog"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/codersdk/agentsdk"
	"github.com/coder/envbuilder"
	"github.com/spf13/cobra"

	// *Never* remove this. Certificates are not bundled as part
	// of the container, so this is necessary for all connections
	// to not be insecure.
	_ "github.com/breml/rootcerts"
)

func main() {
	root := &cobra.Command{
		Use: "envbuilder",
		// Hide usage because we don't want to show the
		// "envbuilder [command] --help" output on error.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			options := envbuilder.OptionsFromEnv(os.LookupEnv)

			var sendLogs func(ctx context.Context, log ...agentsdk.Log) error
			agentURL := os.Getenv("CODER_AGENT_URL")
			agentToken := os.Getenv("CODER_AGENT_TOKEN")
			if agentToken != "" {
				if agentURL == "" {
					return errors.New("CODER_AGENT_URL must be set if CODER_AGENT_TOKEN is set")
				}
				parsed, err := url.Parse(agentURL)
				if err != nil {
					return err
				}
				client := agentsdk.New(parsed)
				client.SetSessionToken(agentToken)
				client.SDK.HTTPClient = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: options.Insecure,
						},
					},
				}
				var flushAndClose func(ctx context.Context) error
				sendLogs, flushAndClose = agentsdk.LogsSender(agentsdk.ExternalLogSourceID, client.PatchLogs, slog.Logger{})
				defer flushAndClose(cmd.Context())

				// This adds the envbuilder subsystem.
				// If telemetry is enabled in a Coder deployment,
				// this will be reported and help us understand
				// envbuilder usage.
				subsystems := os.Getenv("CODER_AGENT_SUBSYSTEM")
				if subsystems != "" {
					subsystems += ","
				}
				subsystems += string(codersdk.AgentSubsystemEnvbuilder)
				os.Setenv("CODER_AGENT_SUBSYSTEM", subsystems)
			}

			options.Logger = func(level codersdk.LogLevel, format string, args ...interface{}) {
				output := fmt.Sprintf(format, args...)
				fmt.Fprintln(cmd.ErrOrStderr(), output)
				if sendLogs != nil {
					sendLogs(cmd.Context(), agentsdk.Log{
						CreatedAt: time.Now(),
						Output:    output,
						Level:     level,
					})
				}
			}
			err := envbuilder.Run(cmd.Context(), options)
			if err != nil {
				options.Logger(codersdk.LogLevelError, "error: %s", err)
			}
			return err
		},
	}
	err := root.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}
}
