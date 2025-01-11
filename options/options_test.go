package options_test

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/coder/envbuilder/options"

	"github.com/coder/serpent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvOptionParsing tests that given environment variables of different types are handled as expected.
func TestEnvOptionParsing(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		const val = "setup.sh"
		t.Setenv(options.WithEnvPrefix("SETUP_SCRIPT"), val)
		o := runCLI()
		require.Equal(t, o.SetupScript, val)
	})

	t.Run("int", func(t *testing.T) {
		t.Setenv(options.WithEnvPrefix("CACHE_TTL_DAYS"), "7")
		o := runCLI()
		require.Equal(t, o.CacheTTLDays, int64(7))
	})

	t.Run("string array", func(t *testing.T) {
		t.Setenv(options.WithEnvPrefix("IGNORE_PATHS"), "/var,/temp")
		o := runCLI()
		require.Equal(t, o.IgnorePaths, []string{"/var", "/temp"})
	})

	t.Run("bool", func(t *testing.T) {
		t.Run("lowercase", func(t *testing.T) {
			t.Setenv(options.WithEnvPrefix("SKIP_REBUILD"), "true")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "false")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_THINPACK"), "false")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
			require.False(t, o.GitCloneThinPack)
		})

		t.Run("uppercase", func(t *testing.T) {
			t.Setenv(options.WithEnvPrefix("SKIP_REBUILD"), "TRUE")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "FALSE")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_THINPACK"), "FALSE")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
			require.False(t, o.GitCloneThinPack)
		})

		t.Run("numeric", func(t *testing.T) {
			t.Setenv(options.WithEnvPrefix("SKIP_REBUILD"), "1")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "0")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_THINPACK"), "0")
			o := runCLI()
			require.True(t, o.SkipRebuild)
			require.False(t, o.GitCloneSingleBranch)
			require.False(t, o.GitCloneThinPack)
		})

		t.Run("empty", func(t *testing.T) {
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"), "")
			t.Setenv(options.WithEnvPrefix("GIT_CLONE_THINPACK"), "")
			o := runCLI()
			require.False(t, o.GitCloneSingleBranch)
			require.False(t, o.GitCloneThinPack)
		})
	})
}

func TestLegacyEnvVars(t *testing.T) {
	legacyEnvs := map[string]string{
		"SETUP_SCRIPT":             "./setup-legacy-script.sh",
		"INIT_SCRIPT":              "./init-legacy-script.sh",
		"INIT_COMMAND":             "/bin/zsh",
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

	assert.Equal(t, legacyEnvs["SETUP_SCRIPT"], o.SetupScript)
	assert.Equal(t, legacyEnvs["INIT_SCRIPT"], o.InitScript)
	assert.Equal(t, legacyEnvs["INIT_COMMAND"], o.InitCommand)
	assert.Equal(t, legacyEnvs["INIT_ARGS"], o.InitArgs)
	assert.Equal(t, legacyEnvs["CACHE_REPO"], o.CacheRepo)
	assert.Equal(t, legacyEnvs["BASE_IMAGE_CACHE_DIR"], o.BaseImageCacheDir)
	assert.Equal(t, legacyEnvs["LAYER_CACHE_DIR"], o.LayerCacheDir)
	assert.Equal(t, legacyEnvs["DEVCONTAINER_DIR"], o.DevcontainerDir)
	assert.Equal(t, legacyEnvs["DEVCONTAINER_JSON_PATH"], o.DevcontainerJSONPath)
	assert.Equal(t, legacyEnvs["DOCKERFILE_PATH"], o.DockerfilePath)
	assert.Equal(t, legacyEnvs["BUILD_CONTEXT_PATH"], o.BuildContextPath)
	assert.Equal(t, int64(7), o.CacheTTLDays)
	assert.Equal(t, legacyEnvs["DOCKER_CONFIG_BASE64"], o.DockerConfigBase64)
	assert.Equal(t, legacyEnvs["FALLBACK_IMAGE"], o.FallbackImage)
	assert.Equal(t, true, o.ExitOnBuildFailure)
	assert.Equal(t, true, o.ForceSafe)
	assert.Equal(t, true, o.Insecure)
	assert.Equal(t, []string{"/var/run", "/tmp"}, o.IgnorePaths)
	assert.Equal(t, true, o.SkipRebuild)
	assert.Equal(t, legacyEnvs["GIT_URL"], o.GitURL)
	assert.Equal(t, int64(1), o.GitCloneDepth)
	assert.Equal(t, true, o.GitCloneSingleBranch)
	assert.Equal(t, legacyEnvs["GIT_USERNAME"], o.GitUsername)
	assert.Equal(t, legacyEnvs["GIT_PASSWORD"], o.GitPassword)
	assert.Equal(t, legacyEnvs["GIT_SSH_PRIVATE_KEY_PATH"], o.GitSSHPrivateKeyPath)
	assert.Equal(t, legacyEnvs["GIT_HTTP_PROXY_URL"], o.GitHTTPProxyURL)
	assert.Equal(t, legacyEnvs["WORKSPACE_FOLDER"], o.WorkspaceFolder)
	assert.Equal(t, legacyEnvs["SSL_CERT_BASE64"], o.SSLCertBase64)
	assert.Equal(t, legacyEnvs["EXPORT_ENV_FILE"], o.ExportEnvFile)
	assert.Equal(t, legacyEnvs["POST_START_SCRIPT_PATH"], o.PostStartScriptPath)
}

// UpdateGoldenFiles indicates golden files should be updated.
var updateCLIOutputGoldenFiles = flag.Bool("update", false, "update options CLI output .golden files")

// TestCLIOutput tests that the default CLI output is as expected.
func TestCLIOutput(t *testing.T) {
	var o options.Options
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

func runCLI() options.Options {
	var o options.Options
	cmd := serpent.Command{
		Options: o.CLI(),
		Handler: func(inv *serpent.Invocation) error {
			return nil
		},
	}

	i := cmd.Invoke().WithOS()
	i.Args = []string{"--help"}
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
