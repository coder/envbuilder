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

func (s *Spec) compileFeatures(fs billy.Filesystem, devcontainerDir, scratchDir string, containerUser, remoteUser, dockerfileContent string, useBuildContexts bool) (string, map[string]string, error) {
	// If there are no features, we don't need to do anything!
	if len(s.Features) == 0 {
		return dockerfileContent, nil, nil
	}

	featuresDir := filepath.Join(scratchDir, "features")
	if err := fs.MkdirAll(featuresDir, 0o644); err != nil {
		return "", nil, fmt.Errorf("create features directory: %w", err)
	}

	// Pass 1: resolve each raw ref to its canonical featureRef and extract
	// the feature spec. We need all specs before we can resolve ordering
	// since installsAfter/dependsOn live inside devcontainer-feature.json.
	//
	// A worklist is used to recursively resolve dependsOn hard dependencies:
	// each extracted feature's dependsOn entries are added to the worklist so
	// that transitive dependencies are automatically fetched and installed,
	// matching the spec requirement that the install set is the union of
	// user-declared features and all their transitive dependsOn dependencies.
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
	extracted := make(map[string]*extractedFeature, len(s.Features))
	idToRef := make(map[string]string, len(s.Features)) // feature ID → refRaw
	canonicalToRefs := make(map[string][]string, len(s.Features))

	// extractOne extracts a single feature and registers it in the tables.
	extractOne := func(featureRefRaw string, opts map[string]any, fromDep bool) error {
		if _, already := extracted[featureRefRaw]; already {
			return nil
		}
		var (
			featureRef string
			ok         bool
		)
		if _, featureRef, ok = strings.Cut(featureRefRaw, "./"); !ok {
			featureRefParsed, err := name.ParseReference(featureRefRaw)
			if err != nil {
				return fmt.Errorf("parse feature ref %s: %w", featureRefRaw, err)
			}
			featureRef = featureRefParsed.Context().Name()
		}

		featureSha := md5.Sum([]byte(featureRefRaw))
		featureName := fmt.Sprintf("%s-%x", filepath.Base(featureRef), featureSha[:4])
		featureDir := filepath.Join(featuresDir, featureName)
		if err := fs.MkdirAll(featureDir, 0o644); err != nil {
			return err
		}
		spec, err := features.Extract(fs, devcontainerDir, featureDir, featureRefRaw)
		if err != nil {
			return fmt.Errorf("extract feature %s: %w", featureRefRaw, err)
		}

		// Enforce feature equality: per spec, two features with the same ID and
		// version are equal and must only be installed once. If a different raw
		// reference resolves to a feature whose ID is already registered:
		//   - same version → equal features; deduplicate silently.
		//   - different version → conflicting versions; error.
		// See https://containers.dev/implementors/features/#definition-feature-equality
		if existingRef, alreadyID := idToRef[spec.ID]; alreadyID {
			existingEF := extracted[existingRef]
			if existingEF.spec.Version == spec.Version {
				// Equal features (same ID + version): register this ref's canonical
				// so that any dependsOn lookup using this alternate ref still resolves
				// to the already-extracted feature via canonicalToRefs / depCovered.
				canonicalToRefs[featureRef] = append(canonicalToRefs[featureRef], featureRefRaw)
				return nil
			}
			return fmt.Errorf(
				"feature %q is required at conflicting versions: %s (from %s) and %s (from %s); only one version of a feature may be in the install set",
				spec.ID, existingEF.spec.Version, existingRef, spec.Version, featureRefRaw,
			)
		}

		extracted[featureRefRaw] = &extractedFeature{
			featureRef:  featureRef,
			featureName: featureName,
			featureDir:  featureDir,
			spec:        spec,
			opts:        opts,
			fromDep:     fromDep,
		}
		idToRef[spec.ID] = featureRefRaw
		canonicalToRefs[featureRef] = append(canonicalToRefs[featureRef], featureRefRaw)
		return nil
	}

	// Seed the worklist with user-declared features.
	type workItem struct {
		ref     string
		opts    map[string]any
		fromDep bool
	}
	worklist := make([]workItem, 0, len(s.Features))
	for featureRefRaw := range s.Features {
		opts := map[string]any{}
		switch t := s.Features[featureRefRaw].(type) {
		case string:
			// As a shorthand, the value of the `features` property can be provided as a
			// single string. This string is mapped to an option called version.
			// https://containers.dev/implementors/features/#devcontainer-json-properties
			opts["version"] = t
		case map[string]any:
			opts = t
		}
		worklist = append(worklist, workItem{ref: featureRefRaw, opts: opts, fromDep: false})
	}

	// Phase 1: extract all user-declared features. This populates idToRef and
	// canonicalToRefs fully before we follow any dependsOn edges, so that dep
	// refs expressed as feature IDs or canonical names can be resolved without
	// trying to fetch them as bare OCI references.
	for len(worklist) > 0 {
		item := worklist[0]
		worklist = worklist[1:]
		if err := extractOne(item.ref, item.opts, item.fromDep); err != nil {
			return "", nil, err
		}
	}

	// Phase 2: follow dependsOn for every extracted feature and auto-add any
	// transitive deps that are not yet in the install set.
	//
	// depCovered returns true when depRef already maps to an extracted feature,
	// checked by exact key, by feature ID (via idToRef), or by canonical name
	// (via canonicalToRefs — handles "host/repo" matching "host/repo:latest").
	depCovered := func(depRef string) bool {
		if _, ok := extracted[depRef]; ok {
			return true
		}
		if ref, ok := idToRef[depRef]; ok {
			if _, ok := extracted[ref]; ok {
				return true
			}
		}
		if refs, ok := canonicalToRefs[depRef]; ok && len(refs) > 0 {
			return true
		}
		return false
	}

	// enqueueNewDeps adds any un-covered deps of ef to the worklist.
	enqueueNewDeps := func(ef *extractedFeature) {
		for depRef, depOpts := range ef.spec.DependsOn {
			if depCovered(depRef) {
				continue
			}
			// Use the full ref from idToRef if this is a bare feature ID.
			resolvedRef := depRef
			if ref, ok := idToRef[depRef]; ok {
				resolvedRef = ref
			}
			depOptsCopy := make(map[string]any, len(depOpts))
			for k, v := range depOpts {
				depOptsCopy[k] = v
			}
			worklist = append(worklist, workItem{ref: resolvedRef, opts: depOptsCopy, fromDep: true})
		}
	}

	for _, ef := range extracted {
		enqueueNewDeps(ef)
	}
	for len(worklist) > 0 {
		item := worklist[0]
		worklist = worklist[1:]
		if _, already := extracted[item.ref]; already {
			continue
		}
		if err := extractOne(item.ref, item.opts, item.fromDep); err != nil {
			return "", nil, err
		}
		// extractOne may have deduplicated this ref (same ID+version as an
		// already-extracted feature), in which case it is not in extracted.
		if ef := extracted[item.ref]; ef != nil {
			enqueueNewDeps(ef)
		}
	}

	canonicalToRef, ambiguousCanonicals := buildCanonicalToRef(canonicalToRefs)

	// When build contexts are enabled, each canonical ref produces a Docker
	// stage alias and context key. Duplicates would generate an invalid
	// Dockerfile, so reject them early.
	if useBuildContexts {
		for canonical, refs := range ambiguousCanonicals {
			return "", nil, fmt.Errorf("multiple configured features share canonical reference %q (%s); this produces duplicate build stages when build contexts are enabled", canonical, strings.Join(refs, ", "))
		}
	}

	// Validate hard dependencies: every dependsOn entry must resolve to a
	// feature in the extracted set. After the worklist above, all transitive
	// dependencies that could be fetched as OCI refs are present; this catches
	// the case where a dep ref is unresolvable (e.g. ambiguous canonical).
	refRaws := make([]string, 0, len(extracted))
	for refRaw := range extracted {
		refRaws = append(refRaws, refRaw)
	}
	specsByRef := make(map[string]*features.Spec, len(extracted))
	for refRaw, ef := range extracted {
		specsByRef[refRaw] = ef.spec
	}
	featureOrder, err := resolveInstallOrder(refRaws, specsByRef, idToRef, canonicalToRef, ambiguousCanonicals, s.OverrideFeatureInstallOrder)
	if err != nil {
		return "", nil, err
	}

	// Pass 2: compile Dockerfile directives in the resolved order.
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
		// TODO: We should warn that because we were unable to find the remote user,
		// we're going to run as root.
		lines = append(lines, fmt.Sprintf("USER %s", remoteUser))
	}
	return strings.Join(lines, "\n"), featureContexts, nil
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
func resolveInstallOrder(refRaws []string, specs map[string]*features.Spec, idToRef, canonicalToRef map[string]string, ambiguousCanonicals map[string][]string, overrideOrder []string) ([]string, error) {
	n := len(refRaws)
	all := make(map[string]bool, n)
	for _, r := range refRaws {
		all[r] = true
	}

	// Assign roundPriority from overrideFeatureInstallOrder.
	// Entry at index i gets priority (len - i) so earlier entries have higher
	// priority.
	roundPriority := make(map[string]int, len(overrideOrder))
	pinnedSet := make(map[string]bool, len(overrideOrder))
	for i, r := range overrideOrder {
		if all[r] {
			roundPriority[r] = len(overrideOrder) - i
			pinnedSet[r] = true
		}
	}

	// Build the dependency graph: inDegree and successors.
	inDegree := make(map[string]int, n)
	for _, r := range refRaws {
		inDegree[r] = 0
	}
	// preds maps refRaw → set of refRaws it must follow.
	preds := make(map[string]map[string]struct{}, n)
	for _, r := range refRaws {
		preds[r] = make(map[string]struct{})
	}
	addEdge := func(from, to string) {
		// "from" must come after "to"
		if _, ok := preds[from][to]; ok {
			return
		}
		preds[from][to] = struct{}{}
		inDegree[from]++
	}

	for _, r := range refRaws {
		for dep := range specs[r].DependsOn {
			predRef, ok, err := resolveDependencyRef(dep, specs, idToRef, canonicalToRef, ambiguousCanonicals)
			if err != nil {
				return nil, err
			}
			if !ok || !all[predRef] {
				continue
			}
			addEdge(r, predRef)
		}
		// installsAfter is a soft dep: only respected when the feature is NOT
		// in overrideFeatureInstallOrder. Pinned features have their install
		// order dictated by the override list; their installsAfter hints are
		// ignored per the spec ("soft dependencies are respected for Features
		// not in overrideFeatureInstallOrder").
		if pinnedSet[r] {
			continue
		}
		for _, depID := range specs[r].InstallsAfter {
			predRef, ok, err := resolveDependencyRef(depID, specs, idToRef, canonicalToRef, ambiguousCanonicals)
			if err != nil {
				return nil, err
			}
			if !ok || !all[predRef] {
				// Soft dep: only applies when predecessor is in the install set.
				continue
			}
			addEdge(r, predRef)
		}
	}

	// successors maps predecessor → features that depend on it.
	successors := make(map[string][]string, n)
	for r, ps := range preds {
		for p := range ps {
			successors[p] = append(successors[p], r)
		}
	}

	// Validate that overrideFeatureInstallOrder is consistent with the
	// dependency graph: for any two pinned features A and B where A is listed
	// before B in overrideOrder, A must not (transitively or directly) depend
	// on B.
	pinnedList := make([]string, 0, len(overrideOrder))
	for _, r := range overrideOrder {
		if all[r] {
			pinnedList = append(pinnedList, r)
		}
	}
	pinnedIndex := make(map[string]int, len(pinnedList))
	for i, r := range pinnedList {
		pinnedIndex[r] = i
	}
	for _, r := range pinnedList {
		for dep := range specs[r].DependsOn {
			depRef, ok, err := resolveDependencyRef(dep, specs, idToRef, canonicalToRef, ambiguousCanonicals)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if depIdx, isPinned := pinnedIndex[depRef]; isPinned {
				if depIdx > pinnedIndex[r] {
					return nil, fmt.Errorf("overrideFeatureInstallOrder violates dependsOn: %q must be installed before %q", depRef, r)
				}
			}
			// If dep is not pinned, the round-based sort will handle it correctly
			// by not committing r until dep is in installationOrder.
		}
	}

	// Round-based sort (spec §3).
	worklist := make(map[string]bool, n)
	for _, r := range refRaws {
		worklist[r] = true
	}
	installationOrder := make([]string, 0, n)
	installed := make(map[string]bool, n)

	for len(worklist) > 0 {
		// Collect all candidates whose dependencies are fully installed.
		round := make([]string, 0)
		for r := range worklist {
			if inDegree[r] == 0 {
				round = append(round, r)
			}
		}
		if len(round) == 0 {
			// No progress — cycle.
			cycled := make([]string, 0, len(worklist))
			for r := range worklist {
				cycled = append(cycled, r)
			}
			sort.Strings(cycled)
			return nil, fmt.Errorf("cycle detected in feature dependency graph: %s", strings.Join(cycled, ", "))
		}

		// Find the maximum roundPriority among candidates.
		maxPriority := 0
		for _, r := range round {
			if roundPriority[r] > maxPriority {
				maxPriority = roundPriority[r]
			}
		}

		// Commit only those with the max priority; return the rest to the
		// worklist for subsequent rounds.
		toCommit := make([]string, 0, len(round))
		for _, r := range round {
			if roundPriority[r] == maxPriority {
				toCommit = append(toCommit, r)
			}
		}
		sort.Strings(toCommit) // alphabetical tie-break within a round

		for _, r := range toCommit {
			installationOrder = append(installationOrder, r)
			installed[r] = true
			delete(worklist, r)
			// Reduce in-degree for successors.
			for _, succ := range successors[r] {
				inDegree[succ]--
			}
		}
	}

	return installationOrder, nil
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
