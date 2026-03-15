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

// TestResolveInstallOrderDivergingTree verifies that two user-declared features
// with completely separate dependsOn chains (a "diverging" / "branching" tree)
// are resolved correctly without a false cycle detection.
//
// Scenario:
//
//	A dependsOn [C]     (A → C)
//	B dependsOn [D]     (B → D)
//	C, D have no deps
//
// Expected: C and D must be installed before A and B respectively.
// The exact ordering of C vs D (and A vs B) is implementation-defined, but
// no cycle must be reported and every dep must strictly precede its dependent.
func TestResolveInstallOrderDivergingTree(t *testing.T) {
	t.Parallel()

	specs := map[string]*features.Spec{
		"a:latest": {ID: "a", Version: "1.0.0", Name: "A", DependsOn: map[string]map[string]any{"c:latest": {}}},
		"b:latest": {ID: "b", Version: "1.0.0", Name: "B", DependsOn: map[string]map[string]any{"d:latest": {}}},
		"c:latest": {ID: "c", Version: "1.0.0", Name: "C"},
		"d:latest": {ID: "d", Version: "1.0.0", Name: "D"},
	}
	idToRef := map[string]string{
		"a": "a:latest",
		"b": "b:latest",
		"c": "c:latest",
		"d": "d:latest",
	}

	order, err := resolveInstallOrder(
		[]string{"a:latest", "b:latest", "c:latest", "d:latest"},
		specs, idToRef,
		map[string]string{}, map[string][]string{},
		nil, // no override
	)
	require.NoError(t, err, "diverging dependency tree must not be reported as a cycle")
	require.Len(t, order, 4)

	pos := make(map[string]int, 4)
	for i, r := range order {
		pos[r] = i
	}

	// C must precede A (A dependsOn C).
	require.Less(t, pos["c:latest"], pos["a:latest"], "c must be installed before a")
	// D must precede B (B dependsOn D).
	require.Less(t, pos["d:latest"], pos["b:latest"], "d must be installed before b")
}

// TestResolveInstallOrderDivergingTreeWithSharedTransitiveDep verifies that a
// shared transitive dependency (D required by both A directly and C transitively)
// is installed only once and before all its dependents.
//
// Scenario:
//
//	A dependsOn [C, D]
//	B dependsOn [D]
//	C dependsOn [D]
//	D has no deps
//
// Expected order satisfying all constraints: D ... C or B ... A (D first always).
func TestResolveInstallOrderDivergingTreeWithSharedTransitiveDep(t *testing.T) {
	t.Parallel()

	specs := map[string]*features.Spec{
		"a:latest": {ID: "a", Version: "1.0.0", Name: "A", DependsOn: map[string]map[string]any{"c:latest": {}, "d:latest": {}}},
		"b:latest": {ID: "b", Version: "1.0.0", Name: "B", DependsOn: map[string]map[string]any{"d:latest": {}}},
		"c:latest": {ID: "c", Version: "1.0.0", Name: "C", DependsOn: map[string]map[string]any{"d:latest": {}}},
		"d:latest": {ID: "d", Version: "1.0.0", Name: "D"},
	}
	idToRef := map[string]string{
		"a": "a:latest",
		"b": "b:latest",
		"c": "c:latest",
		"d": "d:latest",
	}

	order, err := resolveInstallOrder(
		[]string{"a:latest", "b:latest", "c:latest", "d:latest"},
		specs, idToRef,
		map[string]string{}, map[string][]string{},
		nil,
	)
	require.NoError(t, err, "shared transitive dep must not create a false cycle")
	require.Len(t, order, 4)

	pos := make(map[string]int, 4)
	for i, r := range order {
		pos[r] = i
	}

	require.Less(t, pos["d:latest"], pos["c:latest"], "d must precede c")
	require.Less(t, pos["d:latest"], pos["b:latest"], "d must precede b")
	require.Less(t, pos["d:latest"], pos["a:latest"], "d must precede a")
	require.Less(t, pos["c:latest"], pos["a:latest"], "c must precede a")
}

// TestResolveInstallOrderMutualInstallsAfterDetectedAsCycle verifies that
// when two features in the install set both declare installsAfter pointing to
// each other, the algorithm correctly reports a cycle.  This matches the
// reference TypeScript implementation, which also detects mutual soft-dep
// cycles.
func TestResolveInstallOrderMutualInstallsAfterDetectedAsCycle(t *testing.T) {
	t.Parallel()

	specs := map[string]*features.Spec{
		"c:latest": {ID: "c", Version: "1.0.0", Name: "C", InstallsAfter: []string{"d"}},
		"d:latest": {ID: "d", Version: "1.0.0", Name: "D", InstallsAfter: []string{"c"}},
	}
	idToRef := map[string]string{
		"c": "c:latest",
		"d": "d:latest",
	}

	_, err := resolveInstallOrder(
		[]string{"c:latest", "d:latest"},
		specs, idToRef,
		map[string]string{}, map[string][]string{},
		nil,
	)
	require.ErrorContains(t, err, "cycle detected", "mutual installsAfter must be reported as a cycle")
}

// TestResolveInstallOrderOverrideSemanticMatch verifies that
// overrideFeatureInstallOrder entries are matched against extracted features
// using the same ref-resolution lookup chain (idToRef / canonicalToRef) rather
// than raw string equality.
//
// In this test the override specifies "a" (bare feature ID) while the actual
// extracted ref is "ghcr.io/owner/features/a:1.0.0".  Without semantic
// matching, the override would be silently ignored and the wrong install order
// would result.
func TestResolveInstallOrderOverrideSemanticMatch(t *testing.T) {
	t.Parallel()

	// Two features without deps.  We override with bare ID "a" even though the
	// extracted key is the full tagged ref.
	refA := "ghcr.io/owner/features/a:1.0.0"
	refB := "ghcr.io/owner/features/b:1.0.0"

	specs := map[string]*features.Spec{
		refA: {ID: "a", Version: "1.0.0", Name: "A"},
		refB: {ID: "b", Version: "1.0.0", Name: "B"},
	}
	idToRef := map[string]string{
		"a": refA,
		"b": refB,
	}
	canonicalToRef := map[string]string{
		"ghcr.io/owner/features/a": refA,
		"ghcr.io/owner/features/b": refB,
	}

	// Override using bare ID "b" — should still be recognised and give B
	// higher priority than A (so B is installed first).
	order, err := resolveInstallOrder(
		[]string{refA, refB},
		specs, idToRef,
		canonicalToRef, map[string][]string{},
		[]string{"b"}, // override with bare feature ID
	)
	require.NoError(t, err)
	require.Len(t, order, 2)

	bIdx := -1
	aIdx := -1
	for i, r := range order {
		if r == refB {
			bIdx = i
		}
		if r == refA {
			aIdx = i
		}
	}
	require.Greater(t, bIdx, -1, "b must appear in output")
	require.Greater(t, aIdx, -1, "a must appear in output")
	require.Less(t, bIdx, aIdx, "override must place b before a even when specified by bare ID")
}
