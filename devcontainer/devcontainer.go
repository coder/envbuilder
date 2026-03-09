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
	type extractedFeature struct {
		featureRef  string
		featureName string
		featureDir  string
		spec        *features.Spec
		opts        map[string]any
	}
	extracted := make(map[string]*extractedFeature, len(s.Features))
	idToRef := make(map[string]string, len(s.Features)) // feature ID → refRaw
	for featureRefRaw := range s.Features {
		var (
			featureRef string
			ok         bool
		)
		if _, featureRef, ok = strings.Cut(featureRefRaw, "./"); !ok {
			featureRefParsed, err := name.ParseReference(featureRefRaw)
			if err != nil {
				return "", nil, fmt.Errorf("parse feature ref %s: %w", featureRefRaw, err)
			}
			featureRef = featureRefParsed.Context().Name()
		}

		featureOpts := map[string]any{}
		switch t := s.Features[featureRefRaw].(type) {
		case string:
			// As a shorthand, the value of the `features` property can be provided as a
			// single string. This string is mapped to an option called version.
			// https://containers.dev/implementors/features/#devcontainer-json-properties
			featureOpts["version"] = t
		case map[string]any:
			featureOpts = t
		}

		// It's important for caching that this directory is static.
		// If it changes on each run then the container will not be cached.
		//
		// devcontainers/cli has a very complex method of computing the feature
		// name from the feature reference. We're just going to hash it for simplicity.
		featureSha := md5.Sum([]byte(featureRefRaw))
		featureName := filepath.Base(featureRef)
		featureDir := filepath.Join(featuresDir, fmt.Sprintf("%s-%x", featureName, featureSha[:4]))
		if err := fs.MkdirAll(featureDir, 0o644); err != nil {
			return "", nil, err
		}
		spec, err := features.Extract(fs, devcontainerDir, featureDir, featureRefRaw)
		if err != nil {
			return "", nil, fmt.Errorf("extract feature %s: %w", featureRefRaw, err)
		}
		extracted[featureRefRaw] = &extractedFeature{
			featureRef:  featureRef,
			featureName: featureName,
			featureDir:  featureDir,
			spec:        spec,
			opts:        featureOpts,
		}
		idToRef[spec.ID] = featureRefRaw
	}

	// Resolve installation order, then validate hard dependencies.
	refRaws := make([]string, 0, len(extracted))
	for refRaw := range extracted {
		refRaws = append(refRaws, refRaw)
	}
	specsByRef := make(map[string]*features.Spec, len(extracted))
	for refRaw, ef := range extracted {
		specsByRef[refRaw] = ef.spec
	}
	featureOrder, err := resolveInstallOrder(refRaws, specsByRef, idToRef, s.OverrideFeatureInstallOrder)
	if err != nil {
		return "", nil, err
	}
	if err := validateDependencies(specsByRef, idToRef); err != nil {
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
// Priority (highest to lowest):
//  1. overrideOrder entries (in declared order) — user override wins unconditionally
//  2. installsAfter edges from devcontainer-feature.json — soft ordering via
//     Kahn's topological sort on the unconstrained remainder
//  3. Alphabetical — tie-breaking for determinism and layer cache stability
//
// IDs in installsAfter that don't map to a feature present in the set are
// silently ignored (soft-dep semantics). Returns an error if a cycle is
// detected among the installsAfter edges.
//
// See https://containers.dev/implementors/features/#installation-order
func resolveInstallOrder(refRaws []string, specs map[string]*features.Spec, idToRef map[string]string, overrideOrder []string) ([]string, error) {
	// Step 1: lock in override entries (in declared order), removing them
	// from the free set so they are not subject to topo sorting.
	free := make(map[string]bool, len(refRaws))
	for _, r := range refRaws {
		free[r] = true
	}
	pinned := make([]string, 0, len(overrideOrder))
	for _, r := range overrideOrder {
		if free[r] {
			pinned = append(pinned, r)
			delete(free, r)
		}
	}

	// Step 2: topological sort (Kahn's algorithm) on the free remainder,
	// driven by installsAfter edges. An edge A→B means "B must come before A".
	// Edges pointing outside the free set are ignored.
	inDegree := make(map[string]int, len(free))
	deps := make(map[string][]string, len(free)) // refRaw → refRaws it must follow
	for r := range free {
		inDegree[r] = 0
	}
	for r := range free {
		for _, depID := range specs[r].InstallsAfter {
			// Resolve the ID or ref to a refRaw present in the free set.
			predRef, ok := idToRef[depID]
			if !ok {
				// depID might itself be a raw ref rather than a short ID.
				if free[depID] {
					predRef = depID
					ok = true
				}
			}
			if !ok || !free[predRef] {
				// Predecessor absent or overridden — soft dep, skip.
				continue
			}
			deps[r] = append(deps[r], predRef)
			inDegree[r]++
		}
	}

	// Seed the ready queue with all zero-in-degree nodes, sorted alphabetically
	// so tie-breaking is deterministic.
	ready := make([]string, 0, len(free))
	for r := range free {
		if inDegree[r] == 0 {
			ready = append(ready, r)
		}
	}
	sort.Strings(ready)

	sorted := make([]string, 0, len(free))
	// successors maps predecessor → features that depend on it.
	successors := make(map[string][]string, len(free))
	for r, preds := range deps {
		for _, pred := range preds {
			successors[pred] = append(successors[pred], r)
		}
	}
	for len(ready) > 0 {
		// Pop the first (alphabetically smallest) ready node.
		r := ready[0]
		ready = ready[1:]
		sorted = append(sorted, r)
		// Reduce in-degree for all features that installsAfter r.
		newReady := []string{}
		for _, succ := range successors[r] {
			inDegree[succ]--
			if inDegree[succ] == 0 {
				newReady = append(newReady, succ)
			}
		}
		// Insert new ready nodes in sorted position to preserve alphabetical
		// tie-breaking across the entire queue.
		sort.Strings(newReady)
		ready = append(ready, newReady...)
		sort.Strings(ready)
	}

	if len(sorted) != len(free) {
		// Cycle detected — identify the offending features.
		cycled := make([]string, 0)
		for r := range free {
			if inDegree[r] > 0 {
				cycled = append(cycled, r)
			}
		}
		sort.Strings(cycled)
		return nil, fmt.Errorf("cycle detected in feature installsAfter dependencies: %s", strings.Join(cycled, ", "))
	}

	return append(pinned, sorted...), nil
}

// validateDependencies checks that every hard dependency declared via
// dependsOn in a feature's devcontainer-feature.json is satisfied by the
// set of installed features.
func validateDependencies(specs map[string]*features.Spec, idToRef map[string]string) error {
	for refRaw, spec := range specs {
		for _, depID := range spec.DependsOn {
			_, byID := idToRef[depID]
			_, byRef := specs[depID]
			if !byID && !byRef {
				return fmt.Errorf("feature %q (%s) requires feature %q which is not included", spec.ID, refRaw, depID)
			}
		}
	}
	return nil
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
