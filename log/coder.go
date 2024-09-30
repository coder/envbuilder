package log

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
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

// Coder establishes a connection to the Coder instance located at coderURL and
// authenticates using token. It then establishes a dRPC connection to the Agent
// API and begins sending logs. If the version of Coder does not support the
// Agent API, it will fall back to using the PatchLogs endpoint. The closer is
// used to close the logger and to wait at most logSendGracePeriod for logs to
// be sent. Cancelling the context will close the logs immediately without
// waiting for logs to be sent.
func Coder(ctx context.Context, coderURL *url.URL, token string) (logger Func, closer func(), err error) {
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
		logger, closer = sendLogsV1(ctx, client, metaLogger.Named("send_logs_v1"))
		return logger, closer, nil
	}
	// Note that ctx passed to initRPC will be inherited by the
	// underlying connection, nothing we can do about that here.
	dac, err := initRPC(ctx, client, metaLogger.Named("init_rpc"))
	if err != nil {
		// Logged externally
		return nil, nil, fmt.Errorf("init coder rpc client: %w", err)
	}
	ls := agentsdk.NewLogSender(metaLogger.Named("coder_log_sender"))
	metaLogger.Warn(ctx, "Sending logs via AgentAPI v2", slog.F("coder_version", bi.Version))
	logger, closer = sendLogsV2(ctx, dac, ls, metaLogger.Named("send_logs_v2"))
	var closeOnce sync.Once
	return logger, func() {
		closer()
		closeOnce.Do(func() {
			_ = dac.DRPCConn().Close()
		})
	}, nil
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
	retryCtx, retryCancel := context.WithTimeout(ctx, rpcConnectTimeout)
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
func sendLogsV1(ctx context.Context, client *agentsdk.Client, l slog.Logger) (logger Func, closer func()) {
	// nolint: staticcheck // required for backwards compatibility
	sendLog, flushAndClose := agentsdk.LogsSender(agentsdk.ExternalLogSourceID, client.PatchLogs, slog.Logger{})
	var mu sync.Mutex
	return func(lvl Level, msg string, args ...any) {
			log := agentsdk.Log{
				CreatedAt: time.Now(),
				Output:    fmt.Sprintf(msg, args...),
				Level:     codersdk.LogLevel(lvl),
			}
			mu.Lock()
			defer mu.Unlock()
			if err := sendLog(ctx, log); err != nil {
				l.Warn(ctx, "failed to send logs to Coder", slog.Error(err))
			}
		}, func() {
			ctx, cancel := context.WithTimeout(ctx, logSendGracePeriod)
			defer cancel()
			if err := flushAndClose(ctx); err != nil {
				l.Warn(ctx, "failed to flush logs", slog.Error(err))
			}
		}
}

// sendLogsV2 uses the v2 agent API to send logs. Only compatibile with coder versions >= 2.9.
func sendLogsV2(ctx context.Context, dest agentsdk.LogDest, ls coderLogSender, l slog.Logger) (logger Func, closer func()) {
	sendCtx, sendCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	uid := uuid.New()
	go func() {
		defer close(done)
		if err := ls.SendLoop(sendCtx, dest); err != nil {
			if !errors.Is(err, context.Canceled) {
				l.Warn(ctx, "failed to send logs to Coder", slog.Error(err))
			}
		}
	}()

	var closeOnce sync.Once
	return func(l Level, msg string, args ...any) {
			ls.Enqueue(uid, agentsdk.Log{
				CreatedAt: time.Now(),
				Output:    fmt.Sprintf(msg, args...),
				Level:     codersdk.LogLevel(l),
			})
		}, func() {
			closeOnce.Do(func() {
				// Trigger a flush and wait for logs to be sent.
				ls.Flush(uid)
				ctx, cancel := context.WithTimeout(ctx, logSendGracePeriod)
				defer cancel()
				err := ls.WaitUntilEmpty(ctx)
				if err != nil {
					l.Warn(ctx, "log sender did not empty", slog.Error(err))
				}

				// Stop the send loop.
				sendCancel()
			})

			// Wait for the send loop to finish.
			<-done
		}
}
