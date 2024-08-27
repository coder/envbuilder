package hijack_test

import (
	"context"
	"testing"
	"time"

	"github.com/coder/envbuilder/log/hijack"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestLogrus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	messages := make(chan *logrus.Entry, 1)
	hijack.Logrus(func(entry *logrus.Entry) {
		messages <- entry
	})
	logrus.Infof("Testing!")
	select {
	case <-ctx.Done():
		require.FailNow(t, "timed out")
	case message := <-messages:
		require.Equal(t, "Testing!", message.Message)
	}
}
