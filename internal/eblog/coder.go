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
	"storj.io/drpc"
)

var (
	rpcConnectTimeout  = 10 * time.Second
	logSendGracePeriod = 10 * time.Second
)

// Coder establishes a connection to the Coder instance located at
// coderURL and authenticates using token. It then establishes a
// dRPC connection to the Agent API and begins sending logs.
// The returned function is used to block until all logs are sent.
func Coder(ctx context.Context, coderURL *url.URL, token string) (LogFunc, func(), error) {
	dac, err := connectRPC(ctx, coderURL, token)
	if err != nil {
		return nil, nil, fmt.Errorf("init coder rpc client: %w", err)
	}
	ls := agentsdk.NewLogSender(slog.Make(sloghuman.Sink(os.Stderr)).Named("coder_log_sender").Leveled(slog.LevelError))
	sendLogs, doneFunc := sendLogs(ctx, dac, ls)
	return sendLogs, doneFunc, nil
}

type coderLogSender interface {
	Enqueue(uuid.UUID, ...agentsdk.Log)
	SendLoop(context.Context, agentsdk.LogDest) error
	Flush(uuid.UUID)
	WaitUntilEmpty(context.Context) error
}

func connectRPC(ctx context.Context, coderURL *url.URL, token string) (proto.DRPCAgentClient20, error) {
	client := agentsdk.New(coderURL)
	client.SetSessionToken(token)
	var conn drpc.Conn
	var err error
	retryCtx, retryCancel := context.WithTimeout(context.Background(), rpcConnectTimeout)
	for r := retry.New(100*time.Millisecond, time.Second); r.Wait(retryCtx); {
		// Maximize compatibility.
		c, err := client.ConnectRPC20(ctx)
		if err != nil {
			continue
		}
		conn = c.DRPCConn()
		break
	}
	retryCancel()
	if conn == nil {
		return nil, fmt.Errorf("failed to connect to Coder: %w", err)
	}
	return proto.NewDRPCAgentClient(conn), nil
}

func sendLogs(ctx context.Context, dest agentsdk.LogDest, ls coderLogSender) (LogFunc, func()) {
	metaLogger := slog.Make(sloghuman.Sink(os.Stderr)).Named("coder_log").Leveled(slog.LevelError)
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
