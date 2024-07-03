package eblog_test

import (
	"strings"
	"testing"

	"github.com/coder/envbuilder/internal/eblog"
	"github.com/stretchr/testify/require"
)

func Test_Verbose(t *testing.T) {
	t.Parallel()

	t.Run("true", func(t *testing.T) {
		var sb strings.Builder
		l := eblog.New(&sb, true)
		l(eblog.LevelDebug, "hello")
		l(eblog.LevelInfo, "world")
		require.Equal(t, "hello\nworld\n", sb.String())
	})

	t.Run("false", func(t *testing.T) {
		var sb strings.Builder
		l := eblog.New(&sb, false)
		l(eblog.LevelDebug, "hello")
		l(eblog.LevelInfo, "world")
		require.Equal(t, "world\n", sb.String())
	})
}
