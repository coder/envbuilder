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
		"INIT_SCRIPT":      "echo hello",
		"CACHE_REPO":       "kylecarbs/testing",
		"DOCKERFILE_PATH":  "Dockerfile",
		"FALLBACK_IMAGE":   "ubuntu:latest",
		"FORCE_SAFE":       "true",
		"INSECURE":         "true",
		"REPO_URL":         "https://github.com/coder/coder",
		"WORKSPACE_FOLDER": "/workspaces/coder",
	}
	env := envbuilder.SystemOptions(func(s string) string {
		return opts[s]
	})
	require.Equal(t, "/bin/sh", env.InitCommand)
	require.Equal(t, []string{"-c", "echo hello"}, env.InitArguments)
	require.Equal(t, "kylecarbs/testing", env.CacheRepo)
	require.Equal(t, "Dockerfile", env.DockerfilePath)
	require.Equal(t, "ubuntu:latest", env.FallbackImage)
	require.True(t, env.ForceSafe)
	require.True(t, env.Insecure)
	require.Equal(t, "https://github.com/coder/coder", env.RepoURL)
	require.Equal(t, "/workspaces/coder", env.WorkspaceFolder)
}
