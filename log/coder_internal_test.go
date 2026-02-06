package log

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cdr.dev/slog/sloggers/slogtest"
	"github.com/coder/envbuilder/internal/codervendor/agent/proto"
	"github.com/coder/envbuilder/internal/codervendor/agentsdk"
	"github.com/coder/envbuilder/internal/codervendor/codersdk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoder(t *testing.T) {
	t.Parallel()

	t.Run("V1/OK", func(t *testing.T) {
		t.Parallel()

		token := uuid.NewString()
		gotLogs := make(chan struct{})
		var closeOnce sync.Once
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/buildinfo" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "v2.8.9"}`))
				return
			}
			defer closeOnce.Do(func() { close(gotLogs) })
			tokHdr := r.Header.Get(codersdk.SessionTokenHeader)
			assert.Equal(t, token, tokHdr)
			req, ok := decodeV1Logs(t, w, r)
			if !ok {
				return
			}
			if assert.Len(t, req.Logs, 1) {
				assert.Equal(t, "hello world", req.Logs[0].Output)
				assert.Equal(t, codersdk.LogLevelInfo, req.Logs[0].Level)
			}
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logger, _ := newCoderLogger(ctx, t, srv.URL, token)
		logger(LevelInfo, "hello %s", "world")
		<-gotLogs
	})

	t.Run("V1/Close", func(t *testing.T) {
		t.Parallel()

		var got []agentsdk.Log
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/buildinfo" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "v2.8.9"}`))
				return
			}
			req, ok := decodeV1Logs(t, w, r)
			if !ok {
				return
			}
			got = append(got, req.Logs...)
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logger, closer := newCoderLogger(ctx, t, srv.URL, uuid.NewString())
		logger(LevelInfo, "1")
		logger(LevelInfo, "2")
		closer()
		logger(LevelInfo, "3")
		require.Len(t, got, 2)
		assert.Equal(t, "1", got[0].Output)
		assert.Equal(t, "2", got[1].Output)
	})

	t.Run("V1/ErrUnauthorized", func(t *testing.T) {
		t.Parallel()

		token := uuid.NewString()
		authFailed := make(chan struct{})
		var closeOnce sync.Once
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/buildinfo" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "v2.8.9"}`))
				return
			}
			defer closeOnce.Do(func() { close(authFailed) })
			w.WriteHeader(http.StatusUnauthorized)
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		log, _, err := Coder(ctx, u, token)
		require.NoError(t, err)
		// defer closeLog()
		log(LevelInfo, "hello %s", "world")
		<-authFailed
	})

	t.Run("V1/ErrNotCoder", func(t *testing.T) {
		t.Parallel()

		token := uuid.NewString()
		handlerCalled := make(chan struct{})
		var closeOnce sync.Once
		handler := func(w http.ResponseWriter, r *http.Request) {
			defer closeOnce.Do(func() { close(handlerCalled) })
			_, _ = fmt.Fprintf(w, `hello world`)
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		_, _, err = Coder(ctx, u, token)
		require.ErrorContains(t, err, "get coder build version")
		require.ErrorContains(t, err, "unexpected non-JSON response")
		<-handlerCalled
	})

	// In this test, we just fake out the DRPC server.
	t.Run("V2/OK", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ld := &fakeLogDest{t: t}
		ls := agentsdk.NewLogSender(slogtest.Make(t, nil))
		logFunc, logsDone := sendLogsV2(ctx, ld, ls, slogtest.Make(t, nil))
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
	})

	// In this test, we just fake out the DRPC server.
	t.Run("V2/Close", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ld := &fakeLogDest{t: t}
		ls := agentsdk.NewLogSender(slogtest.Make(t, nil))
		logger, closer := sendLogsV2(ctx, ld, ls, slogtest.Make(t, nil))
		defer closer()

		logger(LevelInfo, "1")
		logger(LevelInfo, "2")
		closer()
		logger(LevelInfo, "3")

		require.Len(t, ld.logs, 2)
	})

	// In this test, we validate that a 401 error on the initial connect
	// results in a retry. When envbuilder initially attempts to connect
	// using the Coder agent token, the workspace build may not yet have
	// completed.
	t.Run("V2/Retry", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		token := uuid.NewString()
		var calls atomic.Int64
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/buildinfo" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "v2.9.0"}`))
				return
			}
			n := calls.Add(1)
			t.Logf("test handler: %s call %d", r.URL.Path, n)
			var code int
			switch n {
			// The first two calls should fail with a 401.
			case 1, 2:
				code = http.StatusUnauthorized
			case 3:
				code = http.StatusOK
			default:
				cancel()
				return
			}
			t.Logf("test handler response: %d", code)
			w.WriteHeader(code)
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		_, _, connectError := Coder(ctx, u, token)
		require.ErrorIs(t, connectError, context.Canceled)
		// Should have retried at least twice.
		require.Greater(t, calls.Load(), int64(2))
	})
}

//nolint:paralleltest // We need to replace a global timeout.
func TestCoderRPCTimeout(t *testing.T) {
	// This timeout is picked with the current subtests in mind, it
	// should not be changed without good reason.
	testReplaceTimeout(t, &rpcConnectTimeout, 500*time.Millisecond)

	// In this test, we just stand up an endpoint that does not
	// do dRPC. We'll try to connect, fail to websocket upgrade
	// and eventually give up after rpcConnectTimeout.
	t.Run("V2/Err", func(t *testing.T) {
		t.Parallel()

		token := uuid.NewString()
		handlerDone := make(chan struct{})
		handlerWait := make(chan struct{})
		var closeOnce sync.Once
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/buildinfo" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "v2.9.0"}`))
				return
			}
			defer closeOnce.Do(func() { close(handlerDone) })
			<-handlerWait
			w.WriteHeader(http.StatusOK)
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), rpcConnectTimeout/2)
		defer cancel()
		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		_, _, err = Coder(ctx, u, token)
		require.ErrorContains(t, err, "failed to WebSocket dial")
		require.ErrorIs(t, err, context.DeadlineExceeded)
		close(handlerWait)
		<-handlerDone
	})

	t.Run("V2/Timeout", func(t *testing.T) {
		t.Parallel()

		token := uuid.NewString()
		handlerDone := make(chan struct{})
		handlerWait := make(chan struct{})
		var closeOnce sync.Once
		handler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/buildinfo" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "v2.9.0"}`))
				return
			}
			defer closeOnce.Do(func() { close(handlerDone) })
			<-handlerWait
			w.WriteHeader(http.StatusOK)
		}
		srv := httptest.NewServer(http.HandlerFunc(handler))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), rpcConnectTimeout*2)
		defer cancel()
		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		_, _, err = Coder(ctx, u, token)
		require.ErrorContains(t, err, "failed to WebSocket dial")
		require.ErrorIs(t, err, context.DeadlineExceeded)
		close(handlerWait)
		<-handlerDone
	})
}

func decodeV1Logs(t *testing.T, w http.ResponseWriter, r *http.Request) (agentsdk.PatchLogs, bool) {
	t.Helper()
	var req agentsdk.PatchLogs
	err := json.NewDecoder(r.Body).Decode(&req)
	if !assert.NoError(t, err) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func newCoderLogger(ctx context.Context, t *testing.T, us string, token string) (Func, func()) {
	t.Helper()
	u, err := url.Parse(us)
	require.NoError(t, err)
	logger, closer, err := Coder(ctx, u, token)
	require.NoError(t, err)
	t.Cleanup(closer)
	return logger, closer
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

func testReplaceTimeout(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	if isParallel(t) {
		t.Fatal("cannot replace timeout in parallel test")
	}
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

func isParallel(t *testing.T) (ret bool) {
	t.Helper()
	// This is a hack to determine if the test is running in parallel
	// via property of t.Setenv.
	defer func() {
		if r := recover(); r != nil {
			ret = true
		}
	}()
	// Random variable name to avoid collisions.
	t.Setenv(fmt.Sprintf("__TEST_CHECK_IS_PARALLEL_%d", rand.Int()), "1")
	return false
}
