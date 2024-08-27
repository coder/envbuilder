package hijack

import (
	"io"

	"github.com/coder/envbuilder/log"
	"github.com/sirupsen/logrus"
)

// Logrus hijacks the logrus logger and calls the callback for each log entry.
// This is an abuse of logrus, the package that Kaniko uses, but it exposes
// no other way to obtain the log entries.
func Logrus(lvl log.Level, callback func(entry *logrus.Entry)) {
	logrus.StandardLogger().SetOutput(io.Discard)
	logrus.StandardLogger().SetLevel(LogrusLevel(lvl))
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

func LogrusLevel(lvl log.Level) logrus.Level {
	switch lvl {
	case log.LevelTrace:
		return logrus.TraceLevel
	case log.LevelDebug:
		return logrus.DebugLevel
	case log.LevelInfo:
		return logrus.InfoLevel
	case log.LevelWarn:
		return logrus.WarnLevel
	case log.LevelError:
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}

func LogLevel(lvl logrus.Level) log.Level {
	switch lvl {
	case logrus.TraceLevel:
		return log.LevelTrace
	case logrus.DebugLevel:
		return log.LevelDebug
	case logrus.InfoLevel:
		return log.LevelInfo
	case logrus.WarnLevel:
		return log.LevelWarn
	default: // Error, Fatal, Panic
		return log.LevelError
	}
}
