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
}

func TestLegacyEnvVars(t *testing.T) {
	legacyEnvs := map[string]string{
		"SETUP_SCRIPT":             "./setup-legacy-script.sh",
		"INIT_SCRIPT":              "sleep infinity",
		"INIT_COMMAND":             "/bin/sh",
		"INIT_ARGS":                "arg1 arg2",
		"CACHE_REPO":               "example-cache-repo",
		"BASE_IMAGE_CACHE_DIR":     "/path/to/base/image/cache",
		"LAYER_CACHE_DIR":          "/path/to/layer/cache",
		"DEVCONTAINER_DIR":         "/path/to/devcontainer/dir",
		"DEVCONTAINER_JSON_PATH":   "/path/to/devcontainer.json",
		"DOCKERFILE_PATH":          "/path/to/Dockerfile",
		"BUILD_CONTEXT_PATH":       "/path/to/build/context",
		"CACHE_TTL_DAYS":           "7",
		"DOCKER_CONFIG_BASE64":     "base64encodedconfig",
		"FALLBACK_IMAGE":           "fallback-image:latest",
		"EXIT_ON_BUILD_FAILURE":    "true",
		"FORCE_SAFE":               "true",
		"INSECURE":                 "true",
		"IGNORE_PATHS":             "/var/run,/tmp",
		"SKIP_REBUILD":             "true",
		"GIT_URL":                  "https://github.com/example/repo.git",
		"GIT_CLONE_DEPTH":          "1",
		"GIT_CLONE_SINGLE_BRANCH":  "true",
		"GIT_USERNAME":             "gituser",
		"GIT_PASSWORD":             "gitpassword",
		"GIT_SSH_PRIVATE_KEY_PATH": "/path/to/private/key",
		"GIT_HTTP_PROXY_URL":       "http://proxy.example.com",
		"WORKSPACE_FOLDER":         "/path/to/workspace/folder",
		"SSL_CERT_BASE64":          "base64encodedcert",
		"EXPORT_ENV_FILE":          "/path/to/export/env/file",
		"POST_START_SCRIPT_PATH":   "/path/to/post/start/script",
	}
	for k, v := range legacyEnvs {
		t.Setenv(k, v)
	}

	o := runCLI()

	require.Equal(t, o.SetupScript, legacyEnvs["SETUP_SCRIPT"])
	require.Equal(t, o.InitScript, legacyEnvs["INIT_SCRIPT"])
	require.Equal(t, o.InitCommand, legacyEnvs["INIT_COMMAND"])
	require.Equal(t, o.InitArgs, legacyEnvs["INIT_ARGS"])
	require.Equal(t, o.CacheRepo, legacyEnvs["CACHE_REPO"])
	require.Equal(t, o.BaseImageCacheDir, legacyEnvs["BASE_IMAGE_CACHE_DIR"])
	require.Equal(t, o.LayerCacheDir, legacyEnvs["LAYER_CACHE_DIR"])
	require.Equal(t, o.DevcontainerDir, legacyEnvs["DEVCONTAINER_DIR"])
	require.Equal(t, o.DevcontainerJSONPath, legacyEnvs["DEVCONTAINER_JSON_PATH"])
	require.Equal(t, o.DockerfilePath, legacyEnvs["DOCKERFILE_PATH"])
	require.Equal(t, o.BuildContextPath, legacyEnvs["BUILD_CONTEXT_PATH"])
	require.Equal(t, o.CacheTTLDays, int64(7))
	require.Equal(t, o.DockerConfigBase64, legacyEnvs["DOCKER_CONFIG_BASE64"])
	require.Equal(t, o.FallbackImage, legacyEnvs["FALLBACK_IMAGE"])
	require.Equal(t, o.ExitOnBuildFailure, true)
	require.Equal(t, o.ForceSafe, true)
	require.Equal(t, o.Insecure, true)
	require.Equal(t, o.IgnorePaths, []string{"/var/run", "/tmp"})
	require.Equal(t, o.SkipRebuild, true)
	require.Equal(t, o.GitURL, legacyEnvs["GIT_URL"])
	require.Equal(t, o.GitCloneDepth, int64(1))
	require.Equal(t, o.GitCloneSingleBranch, true)
	require.Equal(t, o.GitUsername, legacyEnvs["GIT_USERNAME"])
	require.Equal(t, o.GitPassword, legacyEnvs["GIT_PASSWORD"])
	require.Equal(t, o.GitSSHPrivateKeyPath, legacyEnvs["GIT_SSH_PRIVATE_KEY_PATH"])
	require.Equal(t, o.GitHTTPProxyURL, legacyEnvs["GIT_HTTP_PROXY_URL"])
	require.Equal(t, o.WorkspaceFolder, legacyEnvs["WORKSPACE_FOLDER"])
	require.Equal(t, o.SSLCertBase64, legacyEnvs["SSL_CERT_BASE64"])
	require.Equal(t, o.ExportEnvFile, legacyEnvs["EXPORT_ENV_FILE"])
	require.Equal(t, o.PostStartScriptPath, legacyEnvs["POST_START_SCRIPT_PATH"])
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
