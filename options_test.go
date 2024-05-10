package envbuilder_test

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/serpent"
	"github.com/stretchr/testify/require"
)

// TestEnvOptionParsing tests that given environment variables of different types are handled as expected.
func TestEnvOptionParsing(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		const val = "setup.sh"
		t.Setenv(envbuilder.WithEnvPrefix("SETUP_SCRIPT"), val)
		o := runCLI()
		require.Equal(t, o.SetupScript, val)
	})

	t.Run("int", func(t *testing.T) {
		t.Setenv(envbuilder.WithEnvPrefix("CACHE_TTL_DAYS"), "7")
		o := runCLI()
		require.Equal(t, o.CacheTTLDays, int64(7))
	})

	t.Run("string array", func(t *testing.T) {
		t.Setenv(envbuilder.WithEnvPrefix("IGNORE_PATHS"), "/var,/temp")
		o := runCLI()
		require.Equal(t, o.IgnorePaths, []string{"/var", "/temp"})
	})

	t.Run("bool", func(t *testing.T) {
		t.Run("lowercase", func(t *testing.T) {
			t.Setenv(envbuilder.WithEnvPrefix("SKIP_REBUILD"), "true")
			t.Setenv(envbuilder.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "false")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
		})

		t.Run("uppercase", func(t *testing.T) {
			t.Setenv(envbuilder.WithEnvPrefix("SKIP_REBUILD"), "TRUE")
			t.Setenv(envbuilder.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "FALSE")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
		})

		t.Run("numeric", func(t *testing.T) {
			t.Setenv(envbuilder.WithEnvPrefix("SKIP_REBUILD"), "1")
			t.Setenv(envbuilder.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "0")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
		})

		t.Run("empty", func(t *testing.T) {
			t.Setenv(envbuilder.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "")
			o := runCLI()
			require.False(t, o.GitCloneSingleBranch)
		})
	})

	t.Run("legacy", func(t *testing.T) {
		legacyEnvValue := "./setup-legacy-script.sh"
		t.Setenv("SETUP_SCRIPT", legacyEnvValue)
		o := runCLI()
		require.Equal(t, o.SetupScript, legacyEnvValue)

		envValue := "./setup-script.sh"
		t.Setenv(envbuilder.WithEnvPrefix("SETUP_SCRIPT"), envValue)
		o = runCLI()
		require.Equal(t, o.SetupScript, envValue)
	})
}

// UpdateGoldenFiles indicates golden files should be updated.
var updateCLIOutputGoldenFiles = flag.Bool("update", false, "update options CLI output .golden files")

// TestCLIOutput tests that the default CLI output is as expected.
func TestCLIOutput(t *testing.T) {
	var o envbuilder.Options
	cmd := serpent.Command{
		Use:     "envbuilder",
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			return nil
		},
	}

	var b ioBufs
	i := cmd.Invoke("--help")
	i.Stdout = &b.Stdout
	i.Stderr = &b.Stderr
	i.Stdin = &b.Stdin

	err := i.Run()
	require.NoError(t, err)

	if *updateCLIOutputGoldenFiles {
		err = os.WriteFile("testdata/options.golden", b.Stdout.Bytes(), 0o644)
		require.NoError(t, err)
		t.Logf("updated golden file: testdata/options.golden")
	} else {
		golden, err := os.ReadFile("testdata/options.golden")
		require.NoError(t, err)
		require.Equal(t, string(golden), b.Stdout.String())
	}
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
