package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"cdr.dev/slog/sloggers/slogtest"
	"github.com/coder/envbuilder/internal/notcodersdk"
	"github.com/coder/serpent"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_sendLogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Random token for testing log fowarding
	agentToken := uuid.NewString()

	// Server to read logs posted by envbuilder. Matched to backlog limit.
	logCh := make(chan notcodersdk.Log, 100)
	logs := make([]notcodersdk.Log, 0)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case log, ok := <-logCh:
				if !ok {
					return
				}
				logs = append(logs, log)
			}
		}
	}()
	logSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, http.MethodPatch, r.Method) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		assert.Equal(t, agentToken, r.Header.Get(notcodersdk.SessionTokenHeader))
		var res notcodersdk.PatchLogs
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&res)) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !assert.Equal(t, notcodersdk.ExternalLogSourceID, res.LogSourceID) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for _, log := range res.Logs {
			logCh <- log
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Make an empty working directory
	tmpDir := t.TempDir()
	t.Setenv("ENVBUILDER_DEVCONTAINER_DIR", tmpDir)
	t.Setenv("ENVBUILDER_DOCKERFILE_DIR", filepath.Join(tmpDir, "Dockerfile"))
	t.Setenv("ENVBUILDER_WORKSPACE_FOLDER", tmpDir)
	t.Setenv("CODER_AGENT_TOKEN", agentToken)
	t.Setenv("CODER_AGENT_URL", logSrv.URL)

	testLogger := slogtest.Make(t, &slogtest.Options{IgnoreErrors: true})
	inv := &serpent.Invocation{
		Command: envbuilderCmd(),
		Args:    []string{},
		Logger:  testLogger,
		Environ: serpent.Environ{},
	}

	err := inv.WithOS().Run()
	require.ErrorContains(t, err, "no such file or directory")
	require.NotEmpty(t, logs)
	require.Contains(t, logs[len(logs)-1].Output, "no such file or directory")
}
