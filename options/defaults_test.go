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
		baseDir  string
		gitURL   string
		expected string
	}{
		{
			name:     "HTTP",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder.git",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "SSH",
			baseDir:  "/workspaces",
			gitURL:   "git@github.com:coder/envbuilder.git",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "username and password",
			baseDir:  "/workspaces",
			gitURL:   "https://username:password@github.com/coder/envbuilder.git",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "trailing",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder.git/",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "trailing-x2",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder.git//",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "no .git",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "trailing no .git",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder/",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "fragment",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder.git#feature-branch",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "fragment-trailing",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder.git/#refs/heads/feature-branch",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "fragment-trailing no .git",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/envbuilder/#refs/heads/feature-branch",
			expected: "/workspaces/envbuilder",
		},
		{
			name:     "space",
			baseDir:  "/workspaces",
			gitURL:   "https://github.com/coder/env%20builder.git",
			expected: "/workspaces/env builder",
		},
		{
			name:     "Unix path",
			baseDir:  "/workspaces",
			gitURL:   "/repo",
			expected: "/workspaces/repo",
		},
		{
			name:     "Unix subpath",
			baseDir:  "/workspaces",
			gitURL:   "/path/to/repo",
			expected: "/workspaces/repo",
		},
		{
			name:     "empty",
			baseDir:  "/workspaces",
			gitURL:   "",
			expected: "/workspaces/empty",
		},
		{
			name:     "non default workspaces folder",
			baseDir:  "/foo",
			gitURL:   "https://github.com/coder/envbuilder.git",
			expected: "/foo/envbuilder",
		},
		{
			name:     "non default workspaces folder empty git URL",
			baseDir:  "/foo",
			gitURL:   "",
			expected: "/foo/empty",
		},
	}
	for _, tt := range successTests {
		t.Run(tt.name, func(t *testing.T) {
			dir := options.DefaultWorkspaceFolder(tt.baseDir, tt.gitURL)
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
		{
			name:       "Unix root",
			invalidURL: "/",
		},
		{
			name:       "Path consists entirely of slash",
			invalidURL: "//",
		},
		{
			name:       "Git URL with no path",
			invalidURL: "http://127.0.0.1:41073",
		},
	}
	for _, tt := range invalidTests {
		t.Run(tt.name, func(t *testing.T) {
			dir := options.DefaultWorkspaceFolder("/workspaces", tt.invalidURL)
			require.Equal(t, "/workspaces/empty", dir)
		})
	}
}

func TestOptions_SetDefaults(t *testing.T) {
	t.Parallel()

	expected := options.Options{
		InitScript:       "sleep infinity",
		InitCommand:      "/bin/sh",
		IgnorePaths:      []string{"/var/run", "/product_uuid", "/product_name"},
		Filesystem:       chmodfs.New(osfs.New("/")),
		GitURL:           "",
		WorkspaceBaseDir: "/workspaces",
		WorkspaceFolder:  "/workspaces/empty",
		MagicDirBase:     "/.envbuilder",
		BinaryPath:       "/.envbuilder/bin/envbuilder",
	}

	var actual options.Options
	actual.SetDefaults()
	assert.Equal(t, expected, actual)
}
