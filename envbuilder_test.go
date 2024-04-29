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
