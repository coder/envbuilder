package eblog

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/sloghuman"
	"github.com/coder/coder/v2/agent/proto"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/codersdk/agentsdk"
	"github.com/coder/retry"
	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

var (
	rpcConnectTimeout  = 10 * time.Second
	logSendGracePeriod = 10 * time.Second
	minAgentAPIV2      = "v2.9"
)

// Coder establishes a connection to the Coder instance located at
// coderURL and authenticates using token. It then establishes a
// dRPC connection to the Agent API and begins sending logs.
// If the version of Coder does not support the Agent API, it will
// fall back to using the PatchLogs endpoint.
// The returned function is used to block until all logs are sent.
func Coder(ctx context.Context, coderURL *url.URL, token string) (LogFunc, func(), error) {
	client := initClient(coderURL, token)
	bi, err := client.SDK.BuildInfo(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("get coder build version: %w", err)
	}
	if semver.Compare(semver.MajorMinor(bi.Version), minAgentAPIV2) < 0 {
		sendLogs, flushLogs := sendLogsV1(ctx, client)
		return sendLogs, flushLogs, nil
	}
	dac, err := initRPC(ctx, client)
	if err != nil {
		return nil, nil, fmt.Errorf("init coder rpc client: %w", err)
	}
	ls := agentsdk.NewLogSender(slog.Make(sloghuman.Sink(os.Stderr)).Named("coder_log_sender").Leveled(slog.LevelError))
	sendLogs, doneFunc := sendLogsV2(ctx, dac, ls)
	return sendLogs, doneFunc, nil
}

type coderLogSender interface {
	Enqueue(uuid.UUID, ...agentsdk.Log)
	SendLoop(context.Context, agentsdk.LogDest) error
	Flush(uuid.UUID)
	WaitUntilEmpty(context.Context) error
}

func initClient(coderURL *url.URL, token string) *agentsdk.Client {
	client := agentsdk.New(coderURL)
	client.SetSessionToken(token)
	return client
}

func initRPC(ctx context.Context, client *agentsdk.Client) (proto.DRPCAgentClient20, error) {
	var c proto.DRPCAgentClient20
	var err error
	retryCtx, retryCancel := context.WithTimeout(context.Background(), rpcConnectTimeout)
	for r := retry.New(100*time.Millisecond, time.Second); r.Wait(retryCtx); {
		// Maximize compatibility.
		c, err = client.ConnectRPC20(ctx)
		if err != nil {
			continue
		}
		break
	}
	retryCancel()
	if c == nil {
		return nil, err
	}
	return proto.NewDRPCAgentClient(c.DRPCConn()), nil
}

// sendLogsV1 uses the PatchLogs endpoint to send logs.
// This is deprecated, but required for backward compatibility with older versions of Coder.
func sendLogsV1(ctx context.Context, client *agentsdk.Client) (LogFunc, func()) {
	// nolint: staticcheck // required for backwards compatibility
	sendLogs, flushLogs := agentsdk.LogsSender(agentsdk.ExternalLogSourceID, client.PatchLogs, slog.Logger{})
	return func(l Level, msg string, args ...any) {
			log := agentsdk.Log{
				CreatedAt: time.Now(),
				Output:    fmt.Sprintf(msg, args...),
				Level:     codersdk.LogLevel(l),
			}
			_ = sendLogs(ctx, log)
		}, func() {
			_ = flushLogs(ctx)
		}
}

// sendLogsV2 uses the v2 agent API to send logs. Only compatibile with coder versions >= 2.9.
func sendLogsV2(ctx context.Context, dest agentsdk.LogDest, ls coderLogSender) (LogFunc, func()) {
	metaLogger := slog.Make(sloghuman.Sink(os.Stderr)).Named("send_logs_v2").Leveled(slog.LevelError)
	done := make(chan struct{})
	uid := uuid.New()
	go func() {
		defer close(done)
		if err := ls.SendLoop(ctx, dest); err != nil {
			if !errors.Is(err, context.Canceled) {
				metaLogger.Error(ctx, "failed to send logs to Coder", slog.Error(err))
			}
		}

		// Wait for up to 10 seconds for logs to finish sending.
		sendCtx, sendCancel := context.WithTimeout(context.Background(), logSendGracePeriod)
		defer sendCancel()
		// Try once more to send any pending logs
		_ = ls.SendLoop(sendCtx, dest)
		ls.Flush(uid)
		_ = ls.WaitUntilEmpty(sendCtx)
	}()

	logFunc := func(l Level, msg string, args ...any) {
		ls.Enqueue(uid, agentsdk.Log{
			CreatedAt: time.Now(),
			Output:    fmt.Sprintf(msg, args...),
			Level:     codersdk.LogLevel(l),
		})
	}

	doneFunc := func() {
		<-done
	}

	return logFunc, doneFunc
}
