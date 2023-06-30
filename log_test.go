package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestHijackLogrus(t *testing.T) {
	messages := make(chan *logrus.Entry, 1)
	envbuilder.HijackLogrus(func(entry *logrus.Entry) {
		messages <- entry
	})
	logrus.Infof("Testing!")
	message := <-messages
	require.Equal(t, "Testing!", message.Message)
}
