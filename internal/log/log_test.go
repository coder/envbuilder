package log_test

import (
	"strings"
	"testing"

	"github.com/coder/envbuilder/internal/log"
	"github.com/stretchr/testify/require"
)

func Test_Verbose(t *testing.T) {
	t.Parallel()

	t.Run("true", func(t *testing.T) {
		var sb strings.Builder
		l := log.New(&sb, true)
		l(log.LevelDebug, "hello")
		l(log.LevelInfo, "world")
		require.Equal(t, "hello\nworld\n", sb.String())
	})

	t.Run("false", func(t *testing.T) {
		var sb strings.Builder
		l := log.New(&sb, false)
		l(log.LevelDebug, "hello")
		l(log.LevelInfo, "world")
		require.Equal(t, "world\n", sb.String())
	})
}
