package eblog

import (
	"context"
	"testing"

	"cdr.dev/slog/sloggers/slogtest"
	"github.com/coder/coder/v2/agent/proto"
	"github.com/coder/coder/v2/codersdk/agentsdk"
	"github.com/stretchr/testify/require"
)

func Test_SendLogs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ld := &fakeLogDest{t: t}
	ls := agentsdk.NewLogSender(slogtest.Make(t, nil))
	logFunc, logsDone := sendLogs(ctx, ld, ls)
	defer logsDone()

	// Send some logs
	for i := 0; i < 10; i++ {
		logFunc(LevelInfo, "info log %d", i+1)
	}

	// Cancel and wait for flush
	cancel()
	t.Logf("cancelled")
	logsDone()

	require.Len(t, ld.logs, 10)
}

type fakeLogDest struct {
	t    testing.TB
	logs []*proto.Log
}

func (d *fakeLogDest) BatchCreateLogs(ctx context.Context, request *proto.BatchCreateLogsRequest) (*proto.BatchCreateLogsResponse, error) {
	d.t.Logf("got %d logs, ", len(request.Logs))
	d.logs = append(d.logs, request.Logs...)
	return &proto.BatchCreateLogsResponse{}, nil
}
