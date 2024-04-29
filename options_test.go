package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/serpent"
	"github.com/stretchr/testify/require"
)

// TestEnvOptionParsing tests that given environment variables of different types are handled as expected.
func TestEnvOptionParsing(t *testing.T) {
	t.Setenv("SETUP_SCRIPT", "setup.sh")
	t.Setenv("CACHE_TTL_DAYS", "7")
	t.Setenv("IGNORE_PATHS", "/var,/tmp")
	t.Setenv("SKIP_REBUILD", "true")
	t.Setenv("GIT_CLONE_SINGLE_BRANCH", "")

	var o envbuilder.Options
	cmd := serpent.Command{
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			return nil
		},
	}
	err := cmd.Invoke().WithOS().Run()
	require.NoError(t, err)

	require.Equal(t, o.SetupScript, "setup.sh")
	require.Equal(t, o.CacheTTLDays, int64(7))
	require.Equal(t, o.IgnorePaths, []string{"/var", "/tmp"})
	require.True(t, o.SkipRebuild)
	require.False(t, o.GitCloneSingleBranch)
}
