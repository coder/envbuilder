package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/stretchr/testify/require"
)

func TestDefaultWorkspaceFolder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		gitURL   string
		expected string
	}{
		{
			name:     "HTTP",
			gitURL:   "https://github.com/coder/envbuilder.git",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "SSH",
			gitURL:   "git@github.com:coder/envbuilder.git",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "empty",
			gitURL:   "",
			expected: envbuilder.EmptyWorkspaceDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := envbuilder.DefaultWorkspaceFolder(tt.gitURL)
			require.NoError(t, err)
			require.Equal(t, tt.expected, dir)
		})
	}
}
