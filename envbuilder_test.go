package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/stretchr/testify/require"
)

func TestDefaultWorkspaceFolder(t *testing.T) {
	t.Parallel()
	dir, err := envbuilder.DefaultWorkspaceFolder("https://github.com/coder/coder")
	require.NoError(t, err)
	require.Equal(t, "/workspaces/coder", dir)

	dir, err = envbuilder.DefaultWorkspaceFolder("")
	require.NoError(t, err)
	require.Equal(t, envbuilder.EmptyWorkspaceDir, dir)
}

func TestSystemOptions(t *testing.T) {
	t.Parallel()
	opts := map[string]string{
		"INIT_SCRIPT":            "echo hello",
		"CACHE_REPO":             "kylecarbs/testing",
		"CACHE_TTL_DAYS":         "30",
		"DEVCONTAINER_JSON_PATH": "/tmp/devcontainer.json",
		"DOCKERFILE_PATH":        "Dockerfile",
		"FALLBACK_IMAGE":         "ubuntu:latest",
		"FORCE_SAFE":             "true",
		"INSECURE":               "false",
		"GIT_CLONE_DEPTH":        "1",
		"GIT_URL":                "https://github.com/coder/coder",
		"WORKSPACE_FOLDER":       "/workspaces/coder",
	}
	env := envbuilder.OptionsFromEnv(func(s string) (string, bool) {
		return opts[s], true
	})
	require.Equal(t, "echo hello", env.InitScript)
	require.Equal(t, "kylecarbs/testing", env.CacheRepo)
	require.Equal(t, "/tmp/devcontainer.json", env.DevcontainerJSONPath)
	require.Equal(t, 30, env.CacheTTLDays)
	require.Equal(t, "Dockerfile", env.DockerfilePath)
	require.Equal(t, "ubuntu:latest", env.FallbackImage)
	require.True(t, env.ForceSafe)
	require.False(t, env.Insecure)
	require.Equal(t, 1, env.GitCloneDepth)
	require.Equal(t, "https://github.com/coder/coder", env.GitURL)
	require.Equal(t, "/workspaces/coder", env.WorkspaceFolder)
}
