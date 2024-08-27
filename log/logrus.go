package log

import (
	"io"

	"github.com/sirupsen/logrus"
)

// HijackLogrus hijacks the logrus logger and calls the callback for each log entry.
// This is an abuse of logrus, the package that Kaniko uses, but it exposes
// no other way to obtain the log entries.
func HijackLogrus(lvl Level, callback func(entry *logrus.Entry)) {
	logrus.StandardLogger().SetOutput(io.Discard)
	logrus.StandardLogger().SetLevel(ToLogrus(lvl))
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

func ToLogrus(lvl Level) logrus.Level {
	switch lvl {
	case LevelTrace:
		return logrus.TraceLevel
	case LevelDebug:
		return logrus.DebugLevel
	case LevelInfo:
		return logrus.InfoLevel
	case LevelWarn:
		return logrus.WarnLevel
	case LevelError:
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}

func FromLogrus(lvl logrus.Level) Level {
	switch lvl {
	case logrus.TraceLevel:
		return LevelTrace
	case logrus.DebugLevel:
		return LevelDebug
	case logrus.InfoLevel:
		return LevelInfo
	case logrus.WarnLevel:
		return LevelWarn
	default: // Error, Fatal, Panic
		return LevelError
	}
}
