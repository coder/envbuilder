package envbuilder_test

import (
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/constants"

	"github.com/stretchr/testify/require"
)

func TestDefaultWorkspaceFolder(t *testing.T) {
	t.Parallel()

	successTests := []struct {
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
			name:     "username and password",
			gitURL:   "https://username:password@github.com/coder/envbuilder.git",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "fragment",
			gitURL:   "https://github.com/coder/envbuilder.git#feature-branch",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "empty",
			gitURL:   "",
			expected: constants.EmptyWorkspaceDir,
		},
	}
	for _, tt := range successTests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := envbuilder.DefaultWorkspaceFolder(tt.gitURL)
			require.NoError(t, err)
			require.Equal(t, tt.expected, dir)
		})
	}

	invalidTests := []struct {
		name       string
		invalidURL string
	}{
		{
			name:       "simple text",
			invalidURL: "not a valid URL",
		},
		{
			name:       "website URL",
			invalidURL: "www.google.com",
		},
	}
	for _, tt := range invalidTests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := envbuilder.DefaultWorkspaceFolder(tt.invalidURL)
			require.NoError(t, err)
			require.Equal(t, constants.EmptyWorkspaceDir, dir)
		})
	}
}
