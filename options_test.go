package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/stretchr/testify/require"
)

func TestOptionsFromEnv(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"SETUP_SCRIPT":            "echo setup script",
		"INIT_SCRIPT":             "echo init script",
		"INIT_COMMAND":            "/bin/bash",
		"INIT_ARGS":               "-c 'echo init args'",
		"CACHE_REPO":              "kylecarbs/testing",
		"BASE_IMAGE_CACHE_DIR":    "/tmp/cache",
		"LAYER_CACHE_DIR":         "/tmp/cache",
		"DEVCONTAINER_DIR":        "/tmp/devcontainer",
		"DEVCONTAINER_JSON_PATH":  "/tmp/devcontainer.json",
		"DOCKERFILE_PATH":         "Dockerfile",
		"BUILD_CONTEXT_PATH":      "/tmp/buildcontext",
		"CACHE_TTL_DAYS":          "30",
		"DOCKER_CONFIG_BASE64":    "dGVzdA==",
		"FALLBACK_IMAGE":          "ubuntu:latest",
		"EXIT_ON_BUILD_FAILURE":   "true",
		"FORCE_SAFE":              "true",
		"INSECURE":                "false",
		"IGNORE_PATHS":            "/tmp,/var",
		"SKIP_REBUILD":            "true",
		"GIT_URL":                 "https://github.com/coder/coder",
		"GIT_CLONE_DEPTH":         "1",
		"GIT_CLONE_SINGLE_BRANCH": "true",
		"GIT_USERNAME":            "kylecarbs",
		"GIT_PASSWORD":            "password",
		"GIT_HTTP_PROXY_URL":      "http://company-proxy.com:8081",
		"WORKSPACE_FOLDER":        "/workspaces/coder",
		"SSL_CERT_BASE64":         "dGVzdA==",
		"EXPORT_ENV_FILE":         "/tmp/env",
		"POST_START_SCRIPT_PATH":  "/tmp/poststart.sh",
	}
	options := envbuilder.OptionsFromEnv(func(s string) (string, bool) {
		return env[s], true
	})

	require.Equal(t, env["SETUP_SCRIPT"], options.GetString("SetupScript"))
	require.Equal(t, env["INIT_SCRIPT"], options.GetString("InitScript"))
	require.Equal(t, env["INIT_COMMAND"], options.GetString("InitCommand"))
	require.Equal(t, env["INIT_ARGS"], options.GetString("InitArgs"))
	require.Equal(t, env["CACHE_REPO"], options.GetString("CacheRepo"))
	require.Equal(t, env["BASE_IMAGE_CACHE_DIR"], options.GetString("BaseImageCacheDir"))
	require.Equal(t, env["LAYER_CACHE_DIR"], options.GetString("LayerCacheDir"))
	require.Equal(t, env["DEVCONTAINER_DIR"], options.GetString("DevcontainerDir"))
	require.Equal(t, env["DEVCONTAINER_JSON_PATH"], options.GetString("DevcontainerJSONPath"))
	require.Equal(t, env["DOCKERFILE_PATH"], options.GetString("DockerfilePath"))
	require.Equal(t, env["BUILD_CONTEXT_PATH"], options.GetString("BuildContextPath"))
	require.Equal(t, 30, options.GetInt("CacheTTLDays"))
	require.Equal(t, env["DOCKER_CONFIG_BASE64"], options.GetString("DockerConfigBase64"))
	require.Equal(t, env["FALLBACK_IMAGE"], options.GetString("FallbackImage"))
	require.True(t, options.GetBool("ExitOnBuildFailure"))
	require.True(t, options.GetBool("ForceSafe"))
	require.False(t, options.GetBool("Insecure"))
	require.Equal(t, options.GetStringSlice("IgnorePaths"), []string{"/tmp", "/var"})
	require.True(t, options.GetBool("SkipRebuild"))
	require.Equal(t, env["GIT_URL"], options.GetString("GitURL"))
	require.Equal(t, 1, options.GetInt("GitCloneDepth"))
	require.True(t, options.GetBool("GitCloneSingleBranch"))
	require.Equal(t, env["GIT_USERNAME"], options.GetString("GitUsername"))
	require.Equal(t, env["GIT_PASSWORD"], options.GetString("GitPassword"))
	require.Equal(t, env["GIT_HTTP_PROXY_URL"], options.GetString("GitHTTPProxyURL"))
	require.Equal(t, env["WORKSPACE_FOLDER"], options.GetString("WorkspaceFolder"))
	require.Equal(t, env["SSL_CERT_BASE64"], options.GetString("SSLCertBase64"))
	require.Equal(t, env["EXPORT_ENV_FILE"], options.GetString("ExportEnvFile"))
	require.Equal(t, env["POST_START_SCRIPT_PATH"], options.GetString("PostStartScriptPath"))
}
