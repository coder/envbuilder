package envbuilder

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/coder/codersdk"
	"github.com/coder/coder/codersdk/agentsdk"
	"github.com/coder/retry"
	"github.com/sirupsen/logrus"
)

// HijackLogrus hijacks the logrus logger and calls the callback for each log entry.
// This is an abuse of logrus, the package that Kaniko uses, but it exposes
// no other way to obtain the log entries.
func HijackLogrus(callback func(entry *logrus.Entry)) {
	logrus.StandardLogger().SetOutput(io.Discard)
	logrus.StandardLogger().SetFormatter(&logrusFormatter{
		callback: callback,
		empty:    []byte{},
	})
}

type logrusFormatter struct {
	callback func(entry *logrus.Entry)
	empty    []byte
}

func (f *logrusFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	f.callback(entry)
	return f.empty, nil
}

// SendLogsToCoder returns a function that will automatically queue and
// debounce logs to send to Coder.
func SendLogsToCoder(ctx context.Context, client *agentsdk.Client, logf func(format string, args ...any)) (func(log agentsdk.StartupLog), func(), error) {
	// Initialize variables for log management
	queuedLogs := make([]agentsdk.StartupLog, 0)
	var flushLogsTimer *time.Timer
	var logMutex sync.Mutex
	logsFlushed := sync.NewCond(&sync.Mutex{})
	var logsSending bool
	defer func() {
		logMutex.Lock()
		if flushLogsTimer != nil {
			flushLogsTimer.Stop()
		}
		logMutex.Unlock()
	}()

	// sendLogs function uploads the queued logs to the server
	sendLogs := func() {
		// Lock logMutex and check if logs are already being sent
		logMutex.Lock()
		if logsSending {
			logMutex.Unlock()
			return
		}
		if flushLogsTimer != nil {
			flushLogsTimer.Stop()
		}
		if len(queuedLogs) == 0 {
			logMutex.Unlock()
			return
		}
		// Move the current queued logs to logsToSend and clear the queue
		logsToSend := queuedLogs
		logsSending = true
		queuedLogs = make([]agentsdk.StartupLog, 0)
		logMutex.Unlock()

		// Retry uploading logs until successful or a specific error occurs
		for r := retry.New(time.Second, 5*time.Second); r.Wait(ctx); {
			err := client.PatchStartupLogs(ctx, agentsdk.PatchStartupLogs{
				Logs: logsToSend,
			})
			if err == nil {
				break
			}
			var sdkErr *codersdk.Error
			if errors.As(err, &sdkErr) {
				if sdkErr.StatusCode() == http.StatusRequestEntityTooLarge {
					logf("startup logs too large, dropping logs")
					break
				}
				if sdkErr.StatusCode() == http.StatusUnauthorized {
					// We just retry! It's likely the build hasn't completed yet.
					continue
				}
			}
			logf("upload startup logs (queued %d): %s", len(logsToSend), err)
		}
		// Reset logsSending flag
		logMutex.Lock()
		logsSending = false
		flushLogsTimer.Reset(100 * time.Millisecond)
		logMutex.Unlock()
		logsFlushed.Broadcast()
	}
	// queueLog function appends a log to the queue and triggers sendLogs if necessary
	queueLog := func(log agentsdk.StartupLog) {
		logMutex.Lock()
		defer logMutex.Unlock()

		// Append log to the queue
		queuedLogs = append(queuedLogs, log)

		// If there are more than 100 logs, send them immediately
		if len(queuedLogs) > 100 {
			// Don't early return after this, because we still want
			// to reset the timer just in case logs come in while
			// we're sending.
			go sendLogs()
		}
		// Reset or set the flushLogsTimer to trigger sendLogs after 100 milliseconds
		if flushLogsTimer != nil {
			flushLogsTimer.Reset(100 * time.Millisecond)
			return
		}
		flushLogsTimer = time.AfterFunc(100*time.Millisecond, sendLogs)
	}

	return func(log agentsdk.StartupLog) {
			queueLog(log)
		}, func() {
			logMutex.Lock()
			defer logMutex.Unlock()
			for len(queuedLogs) > 0 || logsSending {
				logsFlushed.Wait()
			}
		}, nil
}
