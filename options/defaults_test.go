package options_test

import (
	"testing"

	"github.com/coder/envbuilder/internal/chmodfs"
	"github.com/go-git/go-billy/v5/osfs"

	"github.com/stretchr/testify/assert"

	"github.com/coder/envbuilder/options"
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
			expected: options.EmptyWorkspaceDir,
		},
	}
	for _, tt := range successTests {
		t.Run(tt.name, func(t *testing.T) {
			dir := options.DefaultWorkspaceFolder(tt.gitURL)
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
			dir := options.DefaultWorkspaceFolder(tt.invalidURL)
			require.Equal(t, options.EmptyWorkspaceDir, dir)
		})
	}
}

func TestOptions_SetDefaults(t *testing.T) {
	t.Parallel()

	expected := options.Options{
		InitScript:      "sleep infinity",
		InitCommand:     "/bin/sh",
		IgnorePaths:     []string{"/var/run", "/product_uuid", "/product_name"},
		Filesystem:      chmodfs.New(osfs.New("/")),
		GitURL:          "",
		WorkspaceFolder: options.EmptyWorkspaceDir,
		MagicDirBase:    "/.envbuilder",
		BinaryPath:      "/.envbuilder/bin/envbuilder",
	}

	var actual options.Options
	actual.SetDefaults()
	assert.Equal(t, expected, actual)
}
