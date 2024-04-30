package envbuilder_test

import (
	"bytes"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/serpent"
	"github.com/stretchr/testify/require"
)

// TestEnvOptionParsing tests that given environment variables of different types are handled as expected.
func TestEnvOptionParsing(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		const val = "setup.sh"
		t.Setenv("SETUP_SCRIPT", val)
		o := runCLI()
		require.Equal(t, o.SetupScript, val)
	})

	t.Run("int", func(t *testing.T) {
		t.Setenv("CACHE_TTL_DAYS", "7")
		o := runCLI()
		require.Equal(t, o.CacheTTLDays, int64(7))
	})

	t.Run("string array", func(t *testing.T) {
		t.Setenv("IGNORE_PATHS", "/var,/temp")
		o := runCLI()
		require.Equal(t, o.IgnorePaths, []string{"/var", "/temp"})
	})

	t.Run("bool", func(t *testing.T) {
		t.Run("lowercase", func(t *testing.T) {
			t.Setenv("SKIP_REBUILD", "true")
			t.Setenv("GIT_CLONE_SINGLE_BRANCH", "false")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
		})

		t.Run("uppercase", func(t *testing.T) {
			t.Setenv("SKIP_REBUILD", "TRUE")
			t.Setenv("GIT_CLONE_SINGLE_BRANCH", "FALSE")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
		})

		t.Run("numeric", func(t *testing.T) {
			t.Setenv("SKIP_REBUILD", "1")
			t.Setenv("GIT_CLONE_SINGLE_BRANCH", "0")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
		})

		t.Run("empty", func(t *testing.T) {
			t.Setenv("GIT_CLONE_SINGLE_BRANCH", "")
			o := runCLI()
			require.False(t, o.GitCloneSingleBranch)
		})
	})
}

func runCLI() envbuilder.Options {
	var o envbuilder.Options
	cmd := serpent.Command{
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			return nil
		},
	}

	i := cmd.Invoke().WithOS()
	fakeIO(i)
	err := i.Run()

	if err != nil {
		panic("failed to run CLI: " + err.Error())
	}

	return o
}

type ioBufs struct {
	Stdin  bytes.Buffer
	Stdout bytes.Buffer
	Stderr bytes.Buffer
}

func fakeIO(i *serpent.Invocation) *ioBufs {
	var b ioBufs
	i.Stdout = &b.Stdout
	i.Stderr = &b.Stderr
	i.Stdin = &b.Stdin
	return &b
}
