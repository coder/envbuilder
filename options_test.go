package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/serpent"
	"github.com/stretchr/testify/require"
)

// TestStrEnvOptions tests that string env variables can be handled as expected.
func TestStrEnvOptions(t *testing.T) {
	t.Setenv("SETUP_SCRIPT", "setup.sh")
	t.Setenv("INIT_COMMAND", "sleep infinity")

	var o envbuilder.Options
	err := runCLI(&o)
	require.NoError(t, err)

	require.Equal(t, o.SetupScript, "setup.sh")
	require.Equal(t, o.InitCommand, "sleep infinity")
}

// TestIntEnvOptions tests that numeric env variables can be handled as expected.
func TestIntEnvOptions(t *testing.T) {
	t.Setenv("CACHE_TTL_DAYS", "7")

	var o envbuilder.Options
	err := runCLI(&o)
	require.NoError(t, err)

	require.Equal(t, o.CacheTTLDays, 7)
}

// TestMultipleStrEnvOptions tests that numeric env variables can be handled as expected.
func TestMultipleStrEnvOptions(t *testing.T) {
	t.Setenv("CACHE_TTL_DAYS", "7")

	var o envbuilder.Options
	err := runCLI(&o)
	require.NoError(t, err)

	require.Equal(t, o.CacheTTLDays, 7)
}

// TestBoolEnvOptions tests that boolean env variables can be handled as expected.
func TestBoolEnvOptions(t *testing.T) {
	t.Setenv("SKIP_REBUILD", "true")
	t.Setenv("GIT_CLONE_SINGLE_BRANCH", "")
	t.Setenv("EXIT_ON_BUILD_FAILURE", "false")
	t.Setenv("FORCE_SAFE", "TRUE")
	t.Setenv("INSECURE", "FALSE")

	var o envbuilder.Options
	err := runCLI(&o)
	require.NoError(t, err)

	require.True(t, o.SkipRebuild)
	require.False(t, o.GitCloneSingleBranch)
	require.False(t, o.ExitOnBuildFailure)
	require.True(t, o.ForceSafe)
	require.False(t, o.Insecure)
}

func runCLI(o *envbuilder.Options) error {
	cmd := serpent.Command{
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			return nil
		},
	}
	err := cmd.Invoke().WithOS().Run()
	return err
}
