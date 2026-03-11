package devcontainer

import (
	"testing"

	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/stretchr/testify/require"
)

// These tests intentionally live in package devcontainer (not
// devcontainer_test) so they can exercise unexported helper behavior directly.
// The external-package tests in devcontainer_test.go continue to validate
// user-facing behavior through the public API.

func TestBuildCanonicalToRefUnique(t *testing.T) {
	t.Parallel()

	canonicalToRefs := map[string][]string{
		"ghcr.io/example/features/a": {"ghcr.io/example/features/a:1"},
		"ghcr.io/example/features/b": {"ghcr.io/example/features/b:2"},
	}

	canonicalToRef, ambiguous := buildCanonicalToRef(canonicalToRefs)
	require.Empty(t, ambiguous)
	require.Equal(t, "ghcr.io/example/features/a:1", canonicalToRef["ghcr.io/example/features/a"])
	require.Equal(t, "ghcr.io/example/features/b:2", canonicalToRef["ghcr.io/example/features/b"])
}

func TestBuildCanonicalToRefAmbiguousDeferred(t *testing.T) {
	t.Parallel()

	canonicalToRefs := map[string][]string{
		"ghcr.io/example/features/late": {
			"ghcr.io/example/features/late:2.0.0",
			"ghcr.io/example/features/late:1.0.0",
		},
	}

	canonicalToRef, ambiguous := buildCanonicalToRef(canonicalToRefs)
	// buildCanonicalToRef no longer errors; ambiguity is deferred.
	require.Empty(t, canonicalToRef)
	require.Contains(t, ambiguous, "ghcr.io/example/features/late")
	require.Equal(t, []string{
		"ghcr.io/example/features/late:1.0.0",
		"ghcr.io/example/features/late:2.0.0",
	}, ambiguous["ghcr.io/example/features/late"])

	// Ambiguity error surfaces only when the canonical is actually resolved.
	specs := map[string]*features.Spec{}
	idToRef := map[string]string{}
	_, _, err := resolveDependencyRef("ghcr.io/example/features/late", specs, idToRef, canonicalToRef, ambiguous)
	require.ErrorContains(t, err, "ambiguous canonical feature reference \"ghcr.io/example/features/late\"")
	require.ErrorContains(t, err, "ghcr.io/example/features/late:1.0.0, ghcr.io/example/features/late:2.0.0")
}

// TestResolveInstallOrderPinnedFreeDepOK confirms that a pinned feature whose
// dependsOn target is in the free (topo-sorted) set does NOT produce an error.
// The free set is always installed before pinned features, so the ordering
// constraint is automatically satisfied.
func TestResolveInstallOrderPinnedFreeDepOK(t *testing.T) {
	t.Parallel()

	// early depends on late. early is pinned via overrideOrder; late is free.
	specs := map[string]*features.Spec{
		"early:latest": {ID: "early", Version: "1.0.0", Name: "Early", DependsOn: map[string]map[string]any{"late": {}}},
		"late:latest":  {ID: "late", Version: "1.0.0", Name: "Late"},
	}
	idToRef := map[string]string{
		"early": "early:latest",
		"late":  "late:latest",
	}

	order, err := resolveInstallOrder(
		[]string{"early:latest", "late:latest"},
		specs, idToRef,
		map[string]string{}, map[string][]string{},
		[]string{"early:latest"}, // pin early, leaving late free
	)
	require.NoError(t, err)
	// late (free/topo) must precede early (pinned).
	lateIdx := -1
	earlyIdx := -1
	for i, r := range order {
		if r == "late:latest" {
			lateIdx = i
		}
		if r == "early:latest" {
			earlyIdx = i
		}
	}
	require.Greater(t, lateIdx, -1, "late should be in output")
	require.Greater(t, earlyIdx, -1, "early should be in output")
	require.Less(t, lateIdx, earlyIdx, "late (free) must come before early (pinned)")
}

// TestResolveInstallOrderBothPinnedViolationErrors confirms that when both the
// dependent feature AND its dependency are pinned and ordered incorrectly, an
// error is returned.
func TestResolveInstallOrderBothPinnedViolationErrors(t *testing.T) {
	t.Parallel()

	specs := map[string]*features.Spec{
		"early:latest": {ID: "early", Version: "1.0.0", Name: "Early", DependsOn: map[string]map[string]any{"late": {}}},
		"late:latest":  {ID: "late", Version: "1.0.0", Name: "Late"},
	}
	idToRef := map[string]string{
		"early": "early:latest",
		"late":  "late:latest",
	}

	_, err := resolveInstallOrder(
		[]string{"early:latest", "late:latest"},
		specs, idToRef,
		map[string]string{}, map[string][]string{},
		[]string{"early:latest", "late:latest"}, // both pinned, wrong order
	)
	require.ErrorContains(t, err, "overrideFeatureInstallOrder violates dependsOn")
}

// TestResolveInstallOrderPinnedIgnoresInstallsAfter confirms that a pinned
// feature's installsAfter hints are ignored: the override takes precedence
// over soft dependencies per spec.
func TestResolveInstallOrderPinnedIgnoresInstallsAfter(t *testing.T) {
	t.Parallel()

	// top declares installsAfter: ["base"], but top is pinned first in the
	// override. The override should win; base must come AFTER top.
	specs := map[string]*features.Spec{
		"top:latest":  {ID: "top", Version: "1.0.0", Name: "Top", InstallsAfter: []string{"base"}},
		"base:latest": {ID: "base", Version: "1.0.0", Name: "Base"},
	}
	idToRef := map[string]string{
		"top":  "top:latest",
		"base": "base:latest",
	}

	order, err := resolveInstallOrder(
		[]string{"top:latest", "base:latest"},
		specs, idToRef,
		map[string]string{}, map[string][]string{},
		[]string{"top:latest", "base:latest"}, // override: top first
	)
	require.NoError(t, err)
	topIdx, baseIdx := -1, -1
	for i, r := range order {
		if r == "top:latest" {
			topIdx = i
		}
		if r == "base:latest" {
			baseIdx = i
		}
	}
	require.Greater(t, topIdx, -1, "top should be in output")
	require.Greater(t, baseIdx, -1, "base should be in output")
	require.Less(t, topIdx, baseIdx, "override must place top before base despite installsAfter")
}
