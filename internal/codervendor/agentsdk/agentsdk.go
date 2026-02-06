package agentsdk

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/coder/envbuilder/internal/codervendor/codersdk"
)

type Log struct {
	CreatedAt time.Time         `json:"created_at"`
	Output    string            `json:"output"`
	Level     codersdk.LogLevel `json:"level"`
}

type PatchLogs struct {
	LogSourceID uuid.UUID `json:"log_source_id"`
	Logs        []Log     `json:"logs"`
}

// New returns a client that is used to interact with the
// Coder API from a workspace agent.
func New(serverURL *url.URL) *Client {
	return &Client{
		SDK: codersdk.New(serverURL),
	}
}

// Client wraps `codersdk.Client` with specific functions
// scoped to a workspace agent.
type Client struct {
	SDK *codersdk.Client
}

func (c *Client) SetSessionToken(token string) {
	c.SDK.SetSessionToken(token)
}

// PatchLogs writes log messages to the agent startup script.
// Log messages are limited to 1MB in total.
//
// Deprecated: use the DRPCAgentClient.BatchCreateLogs instead
func (c *Client) PatchLogs(ctx context.Context, req PatchLogs) error {
	res, err := c.SDK.Request(ctx, http.MethodPatch, "/api/v2/workspaceagents/me/logs", req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return codersdk.ReadBodyAsError(res)
	}
	return nil
}
