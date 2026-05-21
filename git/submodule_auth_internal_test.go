package git

import (
	"bytes"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/stretchr/testify/require"
)

func TestSubmoduleAuthFor(t *testing.T) {
	t.Parallel()

	type fakeAuth struct{ transport.AuthMethod }
	parentAuth := fakeAuth{}

	cases := []struct {
		name         string
		parentURL    string
		submoduleURL string
		parentAuth   transport.AuthMethod
		wantAuth     transport.AuthMethod
		wantWarn     bool
	}{
		{
			name:         "noParentAuth",
			parentURL:    "https://github.com/org/parent.git",
			submoduleURL: "https://github.com/org/sub.git",
		},
		{
			name:         "sameHostForwards",
			parentURL:    "https://github.com/org/parent.git",
			submoduleURL: "https://github.com/org/sub.git",
			parentAuth:   parentAuth,
			wantAuth:     parentAuth,
		},
		{
			name:         "differentHostWithholdsAndWarns",
			parentURL:    "https://github.com/org/parent.git",
			submoduleURL: "https://evil.com/exfil.git",
			parentAuth:   parentAuth,
			wantWarn:     true,
		},
		{
			name:         "differentHostNoParentAuthNoWarn",
			parentURL:    "https://github.com/org/parent.git",
			submoduleURL: "https://evil.com/exfil.git",
		},
		{
			name:         "scpAndHttpsSameHost",
			parentURL:    "git@github.com:org/parent.git",
			submoduleURL: "https://github.com/org/sub.git",
			parentAuth:   parentAuth,
			wantAuth:     parentAuth,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logf := func(format string, _ ...any) { _, _ = buf.WriteString(format) }
			got := submoduleAuthFor(logf, c.parentURL, c.submoduleURL, c.parentAuth)
			require.Equal(t, c.wantAuth, got)
			if c.wantWarn {
				require.Contains(t, buf.String(), "Not forwarding auth")
			} else {
				require.NotContains(t, buf.String(), "Not forwarding auth")
			}
		})
	}
}

// Once auth is withheld at one level of submodule recursion, it must stay
// withheld for every level below, even when the deeper hosts match each other.
func TestSubmoduleAuthChainStaysWithheld(t *testing.T) {
	t.Parallel()

	type fakeAuth struct{ transport.AuthMethod }
	rootAuth := fakeAuth{}
	logf := func(string, ...any) {}

	level1 := submoduleAuthFor(logf, "https://github.com/org/parent.git", "https://evil.com/repo.git", rootAuth)
	require.Nil(t, level1)

	level2 := submoduleAuthFor(logf, "https://evil.com/repo.git", "https://evil.com/nested.git", level1)
	require.Nil(t, level2)
}
