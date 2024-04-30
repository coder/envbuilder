package envbuilder_test

import (
	"bytes"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/serpent"
	"github.com/stretchr/testify/require"
)

// TestEnvOptionParsing tests that given environment variables of different types are handled as expected.
func TestTestEnvOptionParsing(t *testing.T) {
	t.Run("string", func(t *testing.T) {
	        const val = "setup.sh"
		t.Setenv("SETUP_SCRIPT", val)

		var o envbuilder.Options
		err := runCLI(&o)
		require.NoError(t, err)

		require.Equal(t, o.SetupScript, val)
	})

	t.Run("int", func(t *testing.T) {
		t.Setenv("CACHE_TTL_DAYS", "7")

		var o envbuilder.Options
		err := runCLI(&o)
		require.NoError(t, err)

		require.Equal(t, o.CacheTTLDays, int64(7))
	})

	t.Run("string array", func(t *testing.T) {
		t.Setenv("IGNORE_PATHS", "/var,/temp")

		var o envbuilder.Options
		err := runCLI(&o)
		require.NoError(t, err)

		require.Equal(t, o.IgnorePaths, []string{"/var", "/temp"})
	})

	t.Run("bool", func(t *testing.T) {
		t.Setenv("SKIP_REBUILD", "true")
		t.Setenv("GIT_CLONE_SINGLE_BRANCH", "false")
		t.Setenv("EXIT_ON_BUILD_FAILURE", "true")
		t.Setenv("FORCE_SAFE", "false")
		t.Setenv("INSECURE", "true")

		var o envbuilder.Options
		err := runCLI(&o)
		require.NoError(t, err)

		require.True(t, o.SkipRebuild)
		require.False(t, o.GitCloneSingleBranch)
		require.True(t, o.ExitOnBuildFailure)
		require.False(t, o.ForceSafe)
		require.True(t, o.Insecure)
	})
}

func runCLI(o *envbuilder.Options) error {
	cmd := serpent.Command{
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			return nil
		},
	}
	i := cmd.Invoke().WithOS()
	fakeIO(i)
	err := i.Run()
	return err
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
