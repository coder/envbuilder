package log

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
	// We set a relatively high connection timeout for the initial connection.
	// There is an unfortunate race between the envbuilder container starting and the
	// associated provisioner job completing.
	rpcConnectTimeout  = 30 * time.Second
	logSendGracePeriod = 10 * time.Second
	minAgentAPIV2      = "v2.9"
)

// Coder establishes a connection to the Coder instance located at
// coderURL and authenticates using token. It then establishes a
// dRPC connection to the Agent API and begins sending logs.
// If the version of Coder does not support the Agent API, it will
// fall back to using the PatchLogs endpoint.
// The returned function is used to block until all logs are sent.
func Coder(ctx context.Context, coderURL *url.URL, token string) (Func, func(), error) {
	// To troubleshoot issues, we need some way of logging.
	metaLogger := slog.Make(sloghuman.Sink(os.Stderr))
	defer metaLogger.Sync()
	client := initClient(coderURL, token)
	bi, err := client.SDK.BuildInfo(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("get coder build version: %w", err)
	}
	if semver.Compare(semver.MajorMinor(bi.Version), minAgentAPIV2) < 0 {
		metaLogger.Warn(ctx, "Detected Coder version incompatible with AgentAPI v2, falling back to deprecated API", slog.F("coder_version", bi.Version))
		sendLogs, flushLogs := sendLogsV1(ctx, client, metaLogger.Named("send_logs_v1"))
		return sendLogs, flushLogs, nil
	}
	dac, err := initRPC(ctx, client, metaLogger.Named("init_rpc"))
	if err != nil {
		// Logged externally
		return nil, nil, fmt.Errorf("init coder rpc client: %w", err)
	}
	ls := agentsdk.NewLogSender(metaLogger.Named("coder_log_sender"))
	metaLogger.Warn(ctx, "Sending logs via AgentAPI v2", slog.F("coder_version", bi.Version))
	sendLogs, doneFunc := sendLogsV2(ctx, dac, ls, metaLogger.Named("send_logs_v2"))
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

func initRPC(ctx context.Context, client *agentsdk.Client, l slog.Logger) (proto.DRPCAgentClient20, error) {
	var c proto.DRPCAgentClient20
	var err error
	retryCtx, retryCancel := context.WithTimeout(context.Background(), rpcConnectTimeout)
	defer retryCancel()
	attempts := 0
	for r := retry.New(100*time.Millisecond, time.Second); r.Wait(retryCtx); {
		attempts++
		// Maximize compatibility.
		c, err = client.ConnectRPC20(ctx)
		if err != nil {
			l.Debug(ctx, "Failed to connect to Coder", slog.F("error", err), slog.F("attempt", attempts))
			continue
		}
		break
	}
	if c == nil {
		return nil, err
	}
	return proto.NewDRPCAgentClient(c.DRPCConn()), nil
}

// sendLogsV1 uses the PatchLogs endpoint to send logs.
// This is deprecated, but required for backward compatibility with older versions of Coder.
func sendLogsV1(ctx context.Context, client *agentsdk.Client, l slog.Logger) (Func, func()) {
	// nolint: staticcheck // required for backwards compatibility
	sendLogs, flushLogs := agentsdk.LogsSender(agentsdk.ExternalLogSourceID, client.PatchLogs, slog.Logger{})
	return func(lvl Level, msg string, args ...any) {
			log := agentsdk.Log{
				CreatedAt: time.Now(),
				Output:    fmt.Sprintf(msg, args...),
				Level:     codersdk.LogLevel(lvl),
			}
			if err := sendLogs(ctx, log); err != nil {
				if !errors.Is(err, context.Canceled) {
					l.Warn(ctx, "failed to send logs to Coder", slog.Error(err))
				}
			}
		}, func() {
			// Wait for up to 10 seconds for logs to finish sending.
			sendCtx, sendCancel := context.WithTimeout(context.Background(), logSendGracePeriod)
			defer sendCancel()
			if err := flushLogs(sendCtx); err != nil {
				l.Warn(ctx, "failed to flush logs", slog.Error(err))
			}
			return
		}
}

// sendLogsV2 uses the v2 agent API to send logs. Only compatibile with coder versions >= 2.9.
func sendLogsV2(ctx context.Context, dest agentsdk.LogDest, ls coderLogSender, l slog.Logger) (Func, func()) {
	done := make(chan struct{})
	uid := uuid.New()
	sendLoopCtx, cancelSendLoop := context.WithCancel(ctx)
	defer cancelSendLoop()
	go func() {
		defer close(done)
		if err := ls.SendLoop(sendLoopCtx, dest); err != nil {
			if !errors.Is(err, context.Canceled) {
				l.Warn(ctx, "failed to send logs to Coder", slog.Error(err))
			}
		}

		// Wait for up to 10 seconds for logs to finish sending.
		sendCtx, sendCancel := context.WithTimeout(context.Background(), logSendGracePeriod)
		defer sendCancel()
		// Try once more to send any pending logs
		if err := ls.SendLoop(sendCtx, dest); err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				l.Warn(ctx, "failed to send remaining logs to Coder", slog.Error(err))
			}
		}
		ls.Flush(uid)
		if err := ls.WaitUntilEmpty(sendCtx); err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				l.Warn(ctx, "log sender did not empty", slog.Error(err))
			}
		}
	}()

	logFunc := func(l Level, msg string, args ...any) {
		select {
		case <-sendLoopCtx.Done():
			return
		default:
			ls.Enqueue(uid, agentsdk.Log{
				CreatedAt: time.Now(),
				Output:    fmt.Sprintf(msg, args...),
				Level:     codersdk.LogLevel(l),
			})
		}
	}

	doneFunc := func() {
		cancelSendLoop()
		<-done
	}

	return logFunc, doneFunc
}
