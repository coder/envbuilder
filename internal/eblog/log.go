package eblog

import (
	"fmt"
	"io"
	"strings"

	"github.com/coder/coder/v2/codersdk"
)

type LogFunc func(l Level, msg string, args ...any)

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
func New(w io.Writer, verbose bool) LogFunc {
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

// Wrap wraps the provided LogFuncs into a single LogFunc.
func Wrap(fs ...LogFunc) LogFunc {
	return func(l Level, msg string, args ...any) {
		for _, f := range fs {
			f(l, msg, args...)
		}
	}
}
