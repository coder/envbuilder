package log_test

import (
	"context"
	"testing"
	"time"

	"github.com/coder/envbuilder/log"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestHijackLogrus_Info(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	messages := make(chan *logrus.Entry)

	logf := func(entry *logrus.Entry) {
		t.Logf("got msg level: %s msg: %q", entry.Level, entry.Message)
		messages <- entry
	}

	log.HijackLogrus(log.LevelInfo, logf)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The following should be filtered out.
		logrus.Trace("Tracing!")
		logrus.Debug("Debugging!")
		// We should receive the below.
		logrus.Info("Testing!")
		logrus.Warn("Warning!")
		logrus.Error("Error!")
	}()

	require.Equal(t, "Testing!", rcvCtx(ctx, t, messages).Message)
	require.Equal(t, "Warning!", rcvCtx(ctx, t, messages).Message)
	require.Equal(t, "Error!", rcvCtx(ctx, t, messages).Message)
	<-done
}

func TestHijackLogrus_Debug(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	messages := make(chan *logrus.Entry)

	logf := func(entry *logrus.Entry) {
		t.Logf("got msg level: %s msg: %q", entry.Level, entry.Message)
		messages <- entry
	}

	log.HijackLogrus(log.LevelDebug, logf)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The following should be filtered out.
		logrus.Trace("Tracing!")
		// We should receive the below.
		logrus.Debug("Debugging!")
		logrus.Info("Testing!")
		logrus.Warn("Warning!")
		logrus.Error("Error!")
	}()

	require.Equal(t, "Debugging!", rcvCtx(ctx, t, messages).Message)
	require.Equal(t, "Testing!", rcvCtx(ctx, t, messages).Message)
	require.Equal(t, "Warning!", rcvCtx(ctx, t, messages).Message)
	require.Equal(t, "Error!", rcvCtx(ctx, t, messages).Message)
	<-done
}

func TestHijackLogrus_Error(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	messages := make(chan *logrus.Entry)

	logf := func(entry *logrus.Entry) {
		t.Logf("got msg level: %s msg: %q", entry.Level, entry.Message)
		messages <- entry
	}

	log.HijackLogrus(log.LevelError, logf)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The following should be filtered out.
		logrus.Trace("Tracing!")
		logrus.Debug("Debugging!")
		logrus.Info("Testing!")
		logrus.Warn("Warning!")
		// We should receive the below.
		logrus.Error("Error!")
	}()

	require.Equal(t, "Error!", rcvCtx(ctx, t, messages).Message)
	<-done
}

func rcvCtx[T any](ctx context.Context, t *testing.T, ch <-chan T) (v T) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Fatal("timeout")
	case v = <-ch:
	}
	return v
}
