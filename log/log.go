package log

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/coder/coder/v2/codersdk"
)

type Func func(l Level, msg string, args ...any)

type Level string

// Below constants are the same as their codersdk equivalents.
const (
	LevelTrace = Level(codersdk.LogLevelTrace)
	LevelDebug = Level(codersdk.LogLevelDebug)
	LevelInfo  = Level(codersdk.LogLevelInfo)
	LevelWarn  = Level(codersdk.LogLevelWarn)
	LevelError = Level(codersdk.LogLevelError)
)

// New logs to the provided io.Writer.
func New(w io.Writer, verbose bool) Func {
	return func(l Level, msg string, args ...any) {
		if !verbose {
			switch l {
			case LevelDebug, LevelTrace:
				return
			}
		}
		_, _ = fmt.Fprintf(w, msg, args...)
		if !strings.HasSuffix(msg, "\n") {
			_, _ = fmt.Fprintf(w, "\n")
		}
	}
}

// Wrap wraps the provided LogFuncs into a single Func.
func Wrap(fs ...Func) Func {
	return func(l Level, msg string, args ...any) {
		for _, f := range fs {
			f(l, msg, args...)
		}
	}
}

// Writer returns an io.Writer that logs all writes in a separate goroutine.
// It is the responsibility of the caller to call the returned
// function to stop the goroutine.
func Writer(logf Func) (io.Writer, func()) {
	pipeReader, pipeWriter := io.Pipe()
	doneCh := make(chan struct{})
	go func() {
		defer pipeWriter.Close()
		defer pipeReader.Close()
		scanner := bufio.NewScanner(pipeReader)
		for {
			select {
			case <-doneCh:
				return
			default:
				if !scanner.Scan() {
					return
				}
				logf(LevelInfo, "%s", scanner.Text())
			}
		}
	}()
	closer := func() {
		close(doneCh)
	}
	return pipeWriter, closer
}
