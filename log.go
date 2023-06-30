package envbuilder

import (
	"io"

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
