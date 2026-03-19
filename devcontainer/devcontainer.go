package devcontainer

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GoogleContainerTools/kaniko/pkg/creds"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/go-git/go-billy/v5"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/tailscale/hujson"
)

// Parse parses a devcontainer.json file.
func Parse(content []byte) (*Spec, error) {
	content, err := hujson.Standardize(content)
	if err != nil {
		return nil, fmt.Errorf("standardize json: %w", err)
	}
	var schema Spec
	return &schema, json.Unmarshal(content, &schema)
}

type Spec struct {
	Image         string            `json:"image"`
	Build         BuildSpec         `json:"build"`
	RemoteUser    string            `json:"remoteUser"`
	ContainerUser string            `json:"containerUser"`
	ContainerEnv  map[string]string `json:"containerEnv"`
	RemoteEnv     map[string]string `json:"remoteEnv"`
	// Features is a map of feature names to feature configurations.
	Features map[string]any `json:"features"`
	// OverrideFeatureInstallOrder overrides the order in which features are
	// installed. Feature references not present in this list are installed
	// after the listed ones, in alphabetical order.
	OverrideFeatureInstallOrder []string `json:"overrideFeatureInstallOrder"`
	LifecycleScripts

	// Deprecated but still frequently used...
	Dockerfile string `json:"dockerFile"`
	Context    string `json:"context"`
}

type LifecycleScripts struct {
	OnCreateCommand      LifecycleScript `json:"onCreateCommand"`
	UpdateContentCommand LifecycleScript `json:"updateContentCommand"`
	PostCreateCommand    LifecycleScript `json:"postCreateCommand"`
	PostStartCommand     LifecycleScript `json:"postStartCommand"`
}

type BuildSpec struct {
	Dockerfile string            `json:"dockerfile"`
	Context    string            `json:"context"`
	Args       map[string]string `json:"args"`
	Target     string            `json:"target"`
	CacheFrom  string            `json:"cache_from"`
}

// Compiled is the result of compiling a devcontainer.json file.
type Compiled struct {
	DockerfilePath    string
	DockerfileContent string
	BuildContext      string
	FeatureContexts   map[string]string
	BuildArgs         []string

	User         string
	ContainerEnv map[string]string
	RemoteEnv    map[string]string
}

func SubstituteVars(s string, workspaceFolder string, lookupEnv func(string) (string, bool)) string {
	var buf string
	for {
		beforeOpen, afterOpen, ok := strings.Cut(s, "${")
		if !ok {
			return buf + s
		}
		varExpr, afterClose, ok := strings.Cut(afterOpen, "}")
		if !ok {
			return buf + s
		}

		buf += beforeOpen + substitute(varExpr, workspaceFolder, lookupEnv)
		s = afterClose
	}
}

// Spec for variable substitutions:
// https://containers.dev/implementors/json_reference/#variables-in-devcontainerjson
func substitute(varExpr string, workspaceFolder string, lookupEnv func(string) (string, bool)) string {
	parts := strings.Split(varExpr, ":")
	if len(parts) == 1 {
		switch varExpr {
		case "localWorkspaceFolder", "containerWorkspaceFolder":
			return workspaceFolder
		case "localWorkspaceFolderBasename", "containerWorkspaceFolderBasename":
			return filepath.Base(workspaceFolder)
		default:
			val, ok := lookupEnv(varExpr)
			if ok {
				return val
			}
			return ""
		}
	}
	switch parts[0] {
	case "env", "localEnv", "containerEnv":
		if val, ok := lookupEnv(parts[1]); ok {
			return val
		}
		if len(parts) == 3 {
			return parts[2]
		}
	}
	return ""
}

// HasImage returns true if the devcontainer.json specifies an image.
func (s Spec) HasImage() bool {
	return s.Image != ""
}

// HasDockerfile returns true if the devcontainer.json specifies the path to a
// Dockerfile.
func (s Spec) HasDockerfile() bool {
	return s.Dockerfile != "" || s.Build.Dockerfile != ""
}

// Compile returns the build parameters for the workspace.
// devcontainerDir is the path to the directory where the devcontainer.json file
// is located. scratchDir is the path to the directory where the Dockerfile will
// be written to if one doesn't exist.
func (s *Spec) Compile(fs billy.Filesystem, devcontainerDir, scratchDir string, fallbackDockerfile, workspaceFolder string, useBuildContexts bool, lookupEnv func(string) (string, bool)) (*Compiled, error) {
	params := &Compiled{
		User:         s.ContainerUser,
		ContainerEnv: s.ContainerEnv,
		RemoteEnv:    s.RemoteEnv,
	}

	if s.Image != "" {
		// We just write the image to a file and return it.
		dockerfilePath := filepath.Join(scratchDir, "Dockerfile")
		file, err := fs.OpenFile(dockerfilePath, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open dockerfile: %w", err)
		}
		defer file.Close()
		_, err = file.Write([]byte("FROM " + s.Image))
		if err != nil {
			return nil, err
		}
		params.DockerfilePath = dockerfilePath
		params.BuildContext = scratchDir
	} else {
		// Deprecated values!
		if s.Dockerfile != "" {
			s.Build.Dockerfile = s.Dockerfile
		}
		if s.Context != "" {
			s.Build.Context = s.Context
		}

		if s.Build.Dockerfile != "" {
			params.DockerfilePath = filepath.Join(devcontainerDir, s.Build.Dockerfile)
		} else {
			params.DockerfilePath = fallbackDockerfile
		}
		params.BuildContext = filepath.Join(devcontainerDir, s.Build.Context)
	}

	// It's critical that the Dockerfile produced is deterministic.
	buildArgkeys := make([]string, 0, len(s.Build.Args))
	for key := range s.Build.Args {
		buildArgkeys = append(buildArgkeys, key)
	}
	sort.Strings(buildArgkeys)

	buildArgs := make([]string, 0)
	for _, key := range buildArgkeys {
		val := SubstituteVars(s.Build.Args[key], workspaceFolder, lookupEnv)
		buildArgs = append(buildArgs, key+"="+val)
	}
	params.BuildArgs = buildArgs

	dockerfile, err := fs.Open(params.DockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("open dockerfile %q: %w", params.DockerfilePath, err)
	}
	defer dockerfile.Close()
	dockerfileContent, err := io.ReadAll(dockerfile)
	if err != nil {
		return nil, err
	}
	params.DockerfileContent = string(dockerfileContent)

	if params.User == "" {
		// We should make a best-effort attempt to find the user.
		// Features must be executed as root, so we need to swap back
		// to the running user afterwards.
		params.User, err = UserFromDockerfile(params.DockerfileContent, BuildArgsMap(params.BuildArgs))
		if err != nil {
			return nil, fmt.Errorf("user from dockerfile: %w", err)
		}
	}
	remoteUser := s.RemoteUser
	if remoteUser == "" {
		remoteUser = params.User
	}
	params.DockerfileContent, params.FeatureContexts, err = s.compileFeatures(fs, devcontainerDir, scratchDir, params.User, remoteUser, params.DockerfileContent, useBuildContexts)
	if err != nil {
		return nil, err
	}
	return params, nil
}

// extractedFeature holds the result of downloading and inspecting a single
// devcontainer feature from its OCI or local reference.
type extractedFeature struct {
	featureRef  string
	featureName string
	featureDir  string
	spec        *features.Spec
	opts        map[string]any
	// fromDep is true when this feature was added automatically to satisfy
	// a dependsOn hard dependency (not explicitly listed by the user).
	fromDep bool
}

// featureWorkItem is a pending feature to be extracted and registered.
type featureWorkItem struct {
	ref     string
	opts    map[string]any
	fromDep bool
}

// featurePlan holds the accumulated state of the feature install-set
// during collection and dependency expansion.
type featurePlan struct {
	fs              billy.Filesystem
	devcontainerDir string
	featuresDir     string

	extracted       map[string]*extractedFeature
	idToRef         map[string]string   // feature ID → refRaw
	canonicalToRefs map[string][]string // canonical name → []refRaw

	canonicalToRef      map[string]string   // built after collection
	ambiguousCanonicals map[string][]string // built after collection
}

func newFeaturePlan(fs billy.Filesystem, devcontainerDir, featuresDir string, featureCount int) *featurePlan {
	return &featurePlan{
		fs:              fs,
		devcontainerDir: devcontainerDir,
		featuresDir:     featuresDir,
		extracted:       make(map[string]*extractedFeature, featureCount),
		idToRef:         make(map[string]string, featureCount),
		canonicalToRefs: make(map[string][]string, featureCount),
	}
}

// extractAndRegister downloads, inspects, and deduplicates a single feature.
// It returns true if the feature was newly added (not a duplicate).
func (p *featurePlan) extractAndRegister(featureRefRaw string, opts map[string]any, fromDep bool) (bool, error) {
	if _, already := p.extracted[featureRefRaw]; already {
		return false, nil
	}

	var (
		featureRef string
		ok         bool
	)
	if _, featureRef, ok = strings.Cut(featureRefRaw, "./"); !ok {
		featureRefParsed, err := name.ParseReference(featureRefRaw)
		if err != nil {
			return false, fmt.Errorf("parse feature ref %s: %w", featureRefRaw, err)
		}
		featureRef = featureRefParsed.Context().Name()
	}

	featureSha := md5.Sum([]byte(featureRefRaw))
	featureName := fmt.Sprintf("%s-%x", filepath.Base(featureRef), featureSha[:4])
	featureDir := filepath.Join(p.featuresDir, featureName)
	if err := p.fs.MkdirAll(featureDir, 0o644); err != nil {
		return false, err
	}
	spec, err := features.Extract(p.fs, p.devcontainerDir, featureDir, featureRefRaw)
	if err != nil {
		return false, fmt.Errorf("extract feature %s: %w", featureRefRaw, err)
	}

	// Enforce feature equality: per spec, two features with the same ID and
	// version are equal and must only be installed once. If a different raw
	// reference resolves to a feature whose ID is already registered:
	//   - same version → equal features; deduplicate silently.
	//   - different version → conflicting versions; error.
	// See https://containers.dev/implementors/features/#definition-feature-equality
	if existingRef, alreadyID := p.idToRef[spec.ID]; alreadyID {
		existingEF := p.extracted[existingRef]
		if existingEF.spec.Version == spec.Version {
			p.canonicalToRefs[featureRef] = append(p.canonicalToRefs[featureRef], featureRefRaw)
			return false, nil
		}
		return false, fmt.Errorf(
			"feature %q is required at conflicting versions: %s (from %s) and %s (from %s); only one version of a feature may be in the install set",
			spec.ID, existingEF.spec.Version, existingRef, spec.Version, featureRefRaw,
		)
	}

	p.extracted[featureRefRaw] = &extractedFeature{
		featureRef:  featureRef,
		featureName: featureName,
		featureDir:  featureDir,
		spec:        spec,
		opts:        opts,
		fromDep:     fromDep,
	}
	p.idToRef[spec.ID] = featureRefRaw
	p.canonicalToRefs[featureRef] = append(p.canonicalToRefs[featureRef], featureRefRaw)
	return true, nil
}

// depCovered returns true when depRef already maps to an extracted feature,
// checked by exact key, by feature ID (via idToRef), or by canonical name
// (via canonicalToRefs — handles "host/repo" matching "host/repo:latest").
func (p *featurePlan) depCovered(depRef string) bool {
	if _, ok := p.extracted[depRef]; ok {
		return true
	}
	if ref, ok := p.idToRef[depRef]; ok {
		if _, ok := p.extracted[ref]; ok {
			return true
		}
	}
	if refs, ok := p.canonicalToRefs[depRef]; ok && len(refs) > 0 {
		return true
	}
	return false
}

// enqueueMissingDeps appends worklist items for any dependsOn entries of ef
// that are not yet in the install set.
func (p *featurePlan) enqueueMissingDeps(ef *extractedFeature, worklist *[]featureWorkItem) {
	for depRef, depOpts := range ef.spec.DependsOn {
		if p.depCovered(depRef) {
			continue
		}
		resolvedRef := depRef
		if ref, ok := p.idToRef[depRef]; ok {
			resolvedRef = ref
		}
		depOptsCopy := make(map[string]any, len(depOpts))
		for k, v := range depOpts {
			depOptsCopy[k] = v
		}
		*worklist = append(*worklist, featureWorkItem{ref: resolvedRef, opts: depOptsCopy, fromDep: true})
	}
}

// finalizeLookups builds the canonical-to-ref and ambiguous-canonicals
// lookup tables after collection is complete.
func (p *featurePlan) finalizeLookups() {
	p.canonicalToRef, p.ambiguousCanonicals = buildCanonicalToRef(p.canonicalToRefs)
}

// refRaws returns the set of all extracted raw references.
func (p *featurePlan) refRaws() []string {
	refs := make([]string, 0, len(p.extracted))
	for refRaw := range p.extracted {
		refs = append(refs, refRaw)
	}
	return refs
}

// specsByRef returns a map from raw reference to its feature spec.
func (p *featurePlan) specsByRef() map[string]*features.Spec {
	m := make(map[string]*features.Spec, len(p.extracted))
	for refRaw, ef := range p.extracted {
		m[refRaw] = ef.spec
	}
	return m
}

// normalizeFeatureOptions converts the raw features map from devcontainer.json
// into a worklist of items ready for extraction.
func normalizeFeatureOptions(rawFeatures map[string]any) []featureWorkItem {
	worklist := make([]featureWorkItem, 0, len(rawFeatures))
	for featureRefRaw := range rawFeatures {
		opts := map[string]any{}
		switch t := rawFeatures[featureRefRaw].(type) {
		case string:
			// As a shorthand, the value of the `features` property can be provided as a
			// single string. This string is mapped to an option called version.
			// https://containers.dev/implementors/features/#devcontainer-json-properties
			opts["version"] = t
		case map[string]any:
			opts = t
		}
		worklist = append(worklist, featureWorkItem{ref: featureRefRaw, opts: opts, fromDep: false})
	}
	return worklist
}

// collectFeaturePlan builds the full install set by extracting user-declared
// features and then transitively resolving dependsOn hard dependencies.
func collectFeaturePlan(fs billy.Filesystem, devcontainerDir, featuresDir string, rawFeatures map[string]any) (*featurePlan, error) {
	plan := newFeaturePlan(fs, devcontainerDir, featuresDir, len(rawFeatures))

	// Phase 1: extract all user-declared features. This populates idToRef and
	// canonicalToRefs fully before we follow any dependsOn edges.
	worklist := normalizeFeatureOptions(rawFeatures)
	for len(worklist) > 0 {
		item := worklist[0]
		worklist = worklist[1:]
		if _, err := plan.extractAndRegister(item.ref, item.opts, item.fromDep); err != nil {
			return nil, err
		}
	}

	// Phase 2: follow dependsOn for every extracted feature and auto-add any
	// transitive deps that are not yet in the install set.
	for _, ef := range plan.extracted {
		plan.enqueueMissingDeps(ef, &worklist)
	}
	for len(worklist) > 0 {
		item := worklist[0]
		worklist = worklist[1:]
		if _, already := plan.extracted[item.ref]; already {
			continue
		}
		added, err := plan.extractAndRegister(item.ref, item.opts, item.fromDep)
		if err != nil {
			return nil, err
		}
		if added {
			plan.enqueueMissingDeps(plan.extracted[item.ref], &worklist)
		}
	}

	plan.finalizeLookups()
	return plan, nil
}

// validateBuildContexts rejects ambiguous canonical references when build
// contexts are enabled, since each produces a Docker stage alias.
func (p *featurePlan) validateBuildContexts() error {
	for canonical, refs := range p.ambiguousCanonicals {
		return fmt.Errorf("multiple configured features share canonical reference %q (%s); this produces duplicate build stages when build contexts are enabled", canonical, strings.Join(refs, ", "))
	}
	return nil
}

// emitFeatureDockerfile compiles Dockerfile directives for the resolved
// feature install order and returns the final Dockerfile content and
// build-context map.
func emitFeatureDockerfile(featureOrder []string, extracted map[string]*extractedFeature, dockerfileContent, containerUser, remoteUser string, useBuildContexts bool) (string, map[string]string, error) {
	featureDirectives := make([]string, 0, len(featureOrder))
	featureContexts := make(map[string]string)
	var lines []string

	for _, featureRefRaw := range featureOrder {
		ef := extracted[featureRefRaw]
		fromDirective, directive, err := ef.spec.Compile(ef.featureRef, ef.featureName, ef.featureDir, containerUser, remoteUser, useBuildContexts, ef.opts)
		if err != nil {
			return "", nil, fmt.Errorf("compile feature %s: %w", featureRefRaw, err)
		}
		featureDirectives = append(featureDirectives, directive)
		if useBuildContexts {
			featureContexts[ef.featureRef] = ef.featureDir
			lines = append(lines, fromDirective)
		}
	}

	lines = append(lines, dockerfileContent)
	lines = append(lines, "\nUSER root")
	lines = append(lines, featureDirectives...)
	if remoteUser != "" {
		lines = append(lines, fmt.Sprintf("USER %s", remoteUser))
	}
	return strings.Join(lines, "\n"), featureContexts, nil
}

func (s *Spec) compileFeatures(fs billy.Filesystem, devcontainerDir, scratchDir string, containerUser, remoteUser, dockerfileContent string, useBuildContexts bool) (string, map[string]string, error) {
	if len(s.Features) == 0 {
		return dockerfileContent, nil, nil
	}

	featuresDir := filepath.Join(scratchDir, "features")
	if err := fs.MkdirAll(featuresDir, 0o644); err != nil {
		return "", nil, fmt.Errorf("create features directory: %w", err)
	}

	plan, err := collectFeaturePlan(fs, devcontainerDir, featuresDir, s.Features)
	if err != nil {
		return "", nil, err
	}

	if useBuildContexts {
		if err := plan.validateBuildContexts(); err != nil {
			return "", nil, err
		}
	}

	featureOrder, err := resolveInstallOrder(
		plan.refRaws(), plan.specsByRef(), plan.idToRef,
		plan.canonicalToRef, plan.ambiguousCanonicals,
		s.OverrideFeatureInstallOrder,
	)
	if err != nil {
		return "", nil, err
	}

	return emitFeatureDockerfile(featureOrder, plan.extracted, dockerfileContent, containerUser, remoteUser, useBuildContexts)
}

// resolveInstallOrder determines the final feature installation order.
//
// The algorithm follows the spec's round-based dependency sort:
//  1. Build a DAG with dependsOn (hard) and installsAfter (soft) edges.
//  2. Assign a roundPriority from overrideFeatureInstallOrder: the i-th entry
//     (0-based) receives priority (n - i), all others get 0.
//  3. Execute rounds: each round, collect all features whose deps are fully
//     satisfied (in-degree 0). Of those, commit only the ones with the maximum
//     roundPriority. Tie-break within the committed set alphabetically.
//     Return uncommitted candidates to the worklist for the next round.
//  4. Cycle → error.
//
// This correctly handles overrideFeatureInstallOrder: a pinned feature with
// a free dependency cannot be committed until that dependency's round completes,
// matching the spec requirement that overrides cannot "pull forward" a Feature
// past its own dependency graph.
//
// IDs in installsAfter that don't map to a present feature are silently
// ignored (soft-dep semantics).
//
// See https://containers.dev/implementors/features/#installation-order
// depRefResolver bundles the lookup tables needed to resolve dependency
// references. It avoids threading five maps through every helper.
type depRefResolver struct {
	specs               map[string]*features.Spec
	idToRef             map[string]string
	canonicalToRef      map[string]string
	ambiguousCanonicals map[string][]string
}

func (r *depRefResolver) resolve(dep string) (string, bool, error) {
	return resolveDependencyRef(dep, r.specs, r.idToRef, r.canonicalToRef, r.ambiguousCanonicals)
}

// depGraph holds the directed edge-set used for topological sorting.
type depGraph struct {
	inDegree   map[string]int
	successors map[string][]string
}

// newDepGraph builds a dependency graph from feature specs.
//
// Hard deps (dependsOn) always produce edges. Soft deps (installsAfter) are
// only added for features NOT in pinnedSet, per the spec: "soft dependencies
// are respected for Features not in overrideFeatureInstallOrder".
func newDepGraph(refRaws []string, all map[string]bool, pinnedSet map[string]bool, resolver *depRefResolver) (*depGraph, error) {
	n := len(refRaws)
	inDegree := make(map[string]int, n)
	preds := make(map[string]map[string]struct{}, n)
	for _, r := range refRaws {
		inDegree[r] = 0
		preds[r] = make(map[string]struct{})
	}

	addEdge := func(from, to string) {
		if _, ok := preds[from][to]; ok {
			return
		}
		preds[from][to] = struct{}{}
		inDegree[from]++
	}

	for _, r := range refRaws {
		for dep := range resolver.specs[r].DependsOn {
			predRef, ok, err := resolver.resolve(dep)
			if err != nil {
				return nil, err
			}
			if !ok || !all[predRef] {
				continue
			}
			addEdge(r, predRef)
		}
		if pinnedSet[r] {
			continue
		}
		for _, depID := range resolver.specs[r].InstallsAfter {
			predRef, ok, err := resolver.resolve(depID)
			if err != nil {
				return nil, err
			}
			if !ok || !all[predRef] {
				continue
			}
			addEdge(r, predRef)
		}
	}

	successors := make(map[string][]string, n)
	for r, ps := range preds {
		for p := range ps {
			successors[p] = append(successors[p], r)
		}
	}

	return &depGraph{inDegree: inDegree, successors: successors}, nil
}

// resolveOverrides resolves overrideFeatureInstallOrder entries into
// roundPriority scores and the pinnedSet of features whose order is dictated
// by the override list. Unresolvable entries are silently skipped.
func resolveOverrides(overrideOrder []string, all map[string]bool, resolver *depRefResolver) (roundPriority map[string]int, pinnedSet map[string]bool) {
	roundPriority = make(map[string]int, len(overrideOrder))
	pinnedSet = make(map[string]bool, len(overrideOrder))
	for i, r := range overrideOrder {
		resolvedRef, ok, err := resolver.resolve(r)
		if err != nil || !ok || !all[resolvedRef] {
			continue
		}
		roundPriority[resolvedRef] = len(overrideOrder) - i
		pinnedSet[resolvedRef] = true
	}
	return roundPriority, pinnedSet
}

// validatePinnedOrder checks that overrideFeatureInstallOrder is consistent
// with dependsOn constraints: for any two pinned features A and B where A is
// listed before B, A must not depend on B.
func validatePinnedOrder(overrideOrder []string, pinnedSet map[string]bool, resolver *depRefResolver) error {
	pinnedList := make([]string, 0, len(overrideOrder))
	for _, r := range overrideOrder {
		resolvedRef, ok, err := resolver.resolve(r)
		if err != nil || !ok || !pinnedSet[resolvedRef] {
			continue
		}
		pinnedList = append(pinnedList, resolvedRef)
	}
	pinnedIndex := make(map[string]int, len(pinnedList))
	for i, r := range pinnedList {
		pinnedIndex[r] = i
	}
	for _, r := range pinnedList {
		for dep := range resolver.specs[r].DependsOn {
			depRef, ok, err := resolver.resolve(dep)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if depIdx, isPinned := pinnedIndex[depRef]; isPinned {
				if depIdx > pinnedIndex[r] {
					return fmt.Errorf("overrideFeatureInstallOrder violates dependsOn: %q must be installed before %q", depRef, r)
				}
			}
		}
	}
	return nil
}

// topoSortRounds performs a round-based topological sort (spec §3).
// Within each round, only features sharing the maximum roundPriority are
// committed; ties are broken alphabetically.
func topoSortRounds(g *depGraph, refRaws []string, roundPriority map[string]int) ([]string, error) {
	n := len(refRaws)
	worklist := make(map[string]bool, n)
	for _, r := range refRaws {
		worklist[r] = true
	}
	installationOrder := make([]string, 0, n)

	for len(worklist) > 0 {
		round := make([]string, 0)
		for r := range worklist {
			if g.inDegree[r] == 0 {
				round = append(round, r)
			}
		}
		if len(round) == 0 {
			cycled := make([]string, 0, len(worklist))
			for r := range worklist {
				cycled = append(cycled, r)
			}
			sort.Strings(cycled)
			return nil, fmt.Errorf("cycle detected in feature dependency graph: %s", strings.Join(cycled, ", "))
		}

		maxPriority := 0
		for _, r := range round {
			if roundPriority[r] > maxPriority {
				maxPriority = roundPriority[r]
			}
		}

		toCommit := make([]string, 0, len(round))
		for _, r := range round {
			if roundPriority[r] == maxPriority {
				toCommit = append(toCommit, r)
			}
		}
		sort.Strings(toCommit)

		for _, r := range toCommit {
			installationOrder = append(installationOrder, r)
			delete(worklist, r)
			for _, succ := range g.successors[r] {
				g.inDegree[succ]--
			}
		}
	}

	return installationOrder, nil
}

func resolveInstallOrder(refRaws []string, specs map[string]*features.Spec, idToRef, canonicalToRef map[string]string, ambiguousCanonicals map[string][]string, overrideOrder []string) ([]string, error) {
	all := make(map[string]bool, len(refRaws))
	for _, r := range refRaws {
		all[r] = true
	}

	resolver := &depRefResolver{
		specs:               specs,
		idToRef:             idToRef,
		canonicalToRef:      canonicalToRef,
		ambiguousCanonicals: ambiguousCanonicals,
	}

	roundPriority, pinnedSet := resolveOverrides(overrideOrder, all, resolver)

	g, err := newDepGraph(refRaws, all, pinnedSet, resolver)
	if err != nil {
		return nil, err
	}

	if err := validatePinnedOrder(overrideOrder, pinnedSet, resolver); err != nil {
		return nil, err
	}

	return topoSortRounds(g, refRaws, roundPriority)
}

func resolveDependencyRef(dep string, specs map[string]*features.Spec, idToRef, canonicalToRef map[string]string, ambiguousCanonicals map[string][]string) (string, bool, error) {
	if refRaw, ok := idToRef[dep]; ok {
		return refRaw, true, nil
	}
	if _, ok := specs[dep]; ok {
		return dep, true, nil
	}
	if refRaw, ok := canonicalToRef[dep]; ok {
		return refRaw, true, nil
	}
	if refRaws, ok := ambiguousCanonicals[dep]; ok {
		return "", false, fmt.Errorf("ambiguous canonical feature reference %q matches multiple configured features: %s", dep, strings.Join(refRaws, ", "))
	}
	return "", false, nil
}

func buildCanonicalToRef(canonicalToRefs map[string][]string) (map[string]string, map[string][]string) {
	canonicalToRef := make(map[string]string, len(canonicalToRefs))
	ambiguous := make(map[string][]string)
	for canonicalRef, refRaws := range canonicalToRefs {
		sort.Strings(refRaws)
		if len(refRaws) > 1 {
			ambiguous[canonicalRef] = refRaws
			continue
		}
		canonicalToRef[canonicalRef] = refRaws[0]
	}
	return canonicalToRef, ambiguous
}

// BuildArgsMap converts a slice of "KEY=VALUE" strings to a map.
func BuildArgsMap(buildArgs []string) map[string]string {
	m := make(map[string]string, len(buildArgs))
	for _, arg := range buildArgs {
		if key, val, ok := strings.Cut(arg, "="); ok {
			m[key] = val
		}
	}
	return m
}

// UserFromDockerfile inspects the contents of a provided Dockerfile
// and returns the user that will be used to run the container.
func UserFromDockerfile(dockerfileContent string, buildArgs map[string]string) (user string, err error) {
	res, err := parser.Parse(strings.NewReader(dockerfileContent))
	if err != nil {
		return "", fmt.Errorf("parse dockerfile: %w", err)
	}

	// Collect ARG values (defaults + overrides from buildArgs) for
	// substitution into FROM image refs.
	lexer := shell.NewLex('\\')
	var argEnvs []string
	for _, child := range res.AST.Children {
		if !strings.EqualFold(child.Value, "arg") || child.Next == nil {
			continue
		}
		if key, val, ok := strings.Cut(child.Next.Value, "="); ok {
			if override, has := buildArgs[key]; has {
				val = override
			}
			argEnvs = append(argEnvs, key+"="+val)
		} else {
			arg := child.Next.Value
			if val, has := buildArgs[arg]; has {
				argEnvs = append(argEnvs, arg+"="+val)
			}
		}
	}

	// Parse stages and user commands to determine the relevant user
	// from the final stage.
	var (
		stages       []*instructions.Stage
		stageNames   = make(map[string]*instructions.Stage)
		stageUser    = make(map[*instructions.Stage]*instructions.UserCommand)
		currentStage *instructions.Stage
	)
	for _, child := range res.AST.Children {
		inst, err := instructions.ParseInstruction(child)
		if err != nil {
			return "", fmt.Errorf("parse instruction: %w", err)
		}

		switch i := inst.(type) {
		case *instructions.Stage:
			// Substitute ARG values in the base image name.
			baseName, _, err := lexer.ProcessWord(i.BaseName, shell.EnvsFromSlice(argEnvs))
			if err != nil {
				return "", fmt.Errorf("processing ARG substitution in FROM %q: %w", i.BaseName, err)
			}
			i.BaseName = baseName
			stages = append(stages, i)
			if i.Name != "" {
				stageNames[i.Name] = i
			}
			currentStage = i
		case *instructions.UserCommand:
			if currentStage == nil {
				continue
			}
			stageUser[currentStage] = i
		}
	}

	// Iterate over stages in bottom-up order to find the user,
	// skipping any stages not referenced by the final stage.
	lookupStage := stages[len(stages)-1]
	for i := len(stages) - 1; i >= 0; i-- {
		stage := stages[i]
		if stage != lookupStage {
			continue
		}

		if user, ok := stageUser[stage]; ok {
			return user.User, nil
		}

		// If we reach the scratch stage, we can't determine the user.
		if stage.BaseName == "scratch" {
			return "", nil
		}

		// Check if this FROM references another stage.
		if stage.BaseName != "" {
			var ok bool
			lookupStage, ok = stageNames[stage.BaseName]
			if ok {
				continue
			}
		}

		// If we can't find a user command, try to find the user from
		// the image.
		ref, err := name.ParseReference(strings.TrimSpace(stage.BaseName))
		if err != nil {
			return "", fmt.Errorf("parse image ref %q: %w", stage.BaseName, err)
		}
		user, err := UserFromImage(ref)
		if err != nil {
			return "", fmt.Errorf("user from image %s: %w", ref.Name(), err)
		}
		return user, nil
	}

	return "", nil
}

// ImageFromDockerfile inspects the contents of a provided Dockerfile
// and returns the image that will be used to run the container.
func ImageFromDockerfile(dockerfileContent string, buildArgs map[string]string) (name.Reference, error) {
	lexer := shell.NewLex('\\')
	var args []string
	var imageRef string
	lines := strings.Split(dockerfileContent, "\n")
	// Iterate over lines in reverse
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if arg, ok := strings.CutPrefix(line, "ARG "); ok {
			arg = strings.TrimSpace(arg)
			if key, val, ok := strings.Cut(arg, "="); ok {
				key, _, err := lexer.ProcessWord(key, shell.EnvsFromSlice(args))
				if err != nil {
					return nil, fmt.Errorf("processing %q: %w", line, err)
				}
				val, _, err := lexer.ProcessWord(val, shell.EnvsFromSlice(args))
				if err != nil {
					return nil, fmt.Errorf("processing %q: %w", line, err)
				}
				// Allow buildArgs to override Dockerfile ARG defaults.
				if override, has := buildArgs[key]; has {
					val = override
				}
				args = append(args, key+"="+val)
			} else {
				// ARG without a default — look up in buildArgs.
				if val, has := buildArgs[arg]; has {
					args = append(args, arg+"="+val)
				}
			}
			continue
		}
		if imageRef == "" {
			if fromArgs, ok := strings.CutPrefix(line, "FROM "); ok {
				imageRef = fromArgs
			}
		}
	}
	if imageRef == "" {
		return nil, fmt.Errorf("no FROM directive found")
	}
	imageRef, _, err := lexer.ProcessWord(imageRef, shell.EnvsFromSlice(args))
	if err != nil {
		return nil, fmt.Errorf("processing %q: %w", imageRef, err)
	}
	image, err := name.ParseReference(strings.TrimSpace(imageRef))
	if err != nil {
		return nil, fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}
	return image, nil
}

// UserFromImage inspects the remote reference and returns the user
// that will be used to run the container.
func UserFromImage(ref name.Reference) (string, error) {
	image, err := remote.Image(ref, remote.WithAuthFromKeychain(creds.GetKeychain()))
	if err != nil {
		return "", fmt.Errorf("fetch image %s: %w", ref.Name(), err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		return "", fmt.Errorf("fetch config %s: %w", ref.Name(), err)
	}
	return config.Config.User, nil
}
