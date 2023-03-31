package envbuilder_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/coder/coder/codersdk/agentsdk"
	"github.com/coder/envbuilder"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/zeebo/assert"
)

func TestHijackLogrus(t *testing.T) {
	messages := make(chan *logrus.Entry, 1)
	envbuilder.HijackLogrus(func(entry *logrus.Entry) {
		messages <- entry
	})
	logrus.Infof("Testing!")
	message := <-messages
	require.Equal(t, "Testing!", message.Message)
}

func TestSendLogsToCoder(t *testing.T) {
	t.Parallel()
	queued := make(chan agentsdk.PatchStartupLogs, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req agentsdk.PatchStartupLogs
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)
		queued <- req
	}))
	srvURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	client := agentsdk.New(srvURL)
	sendLog, err := envbuilder.SendLogsToCoder(context.Background(), client, func(format string, args ...any) {
		t.Logf(format, args...)
	})
	require.NoError(t, err)
	sendLog(agentsdk.StartupLog{
		Output: "Hello, world!",
	})
	logs := <-queued
	require.Len(t, logs.Logs, 1)
	require.Equal(t, "Hello, world!", logs.Logs[0].Output)
}
