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
		params.User, err = UserFromDockerfile(params.DockerfileContent, buildArgs)
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
	err := fs.MkdirAll(featuresDir, 0o644)
	if err != nil {
		return "", nil, fmt.Errorf("create features directory: %w", err)
	}
	featureDirectives := []string{}
	featureContexts := make(map[string]string)

	// TODO: Respect the installation order outlined by the spec:
	// https://containers.dev/implementors/features/#installation-order
	featureOrder := []string{}
	for featureRef := range s.Features {
		featureOrder = append(featureOrder, featureRef)
	}
	// It's critical we sort features prior to compilation so the Dockerfile
	// is deterministic which allows for caching.
	sort.Strings(featureOrder)

	var lines []string
	for _, featureRefRaw := range featureOrder {
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
			// As a shorthand, the value of the `features`` property can be provided as a
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
		fromDirective, directive, err := spec.Compile(featureRef, featureName, featureDir, containerUser, remoteUser, useBuildContexts, featureOpts)
		if err != nil {
			return "", nil, fmt.Errorf("compile feature %s: %w", featureRefRaw, err)
		}
		featureDirectives = append(featureDirectives, directive)
		if useBuildContexts {
			featureContexts[featureRef] = featureDir
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
	return strings.Join(lines, "\n"), featureContexts, err
}

// buildArgsWithDefaults merges external build args with ARG defaults from a Dockerfile.
// External args take precedence over Dockerfile defaults.
func buildArgsWithDefaults(dockerfileContent string, externalArgs []string) ([]string, error) {
	lexer := shell.NewLex('\\')

	// Start with external args (these have highest precedence)
	result := make([]string, len(externalArgs))
	copy(result, externalArgs)

	// Build a set of externally-provided arg names for quick lookup
	externalArgNames := make(map[string]struct{})
	for _, arg := range externalArgs {
		if parts := strings.SplitN(arg, "=", 2); len(parts) == 2 {
			externalArgNames[parts[0]] = struct{}{}
		}
	}

	// Process ARG instructions to add default values if not overridden
	for _, line := range strings.Split(dockerfileContent, "\n") {
		arg, ok := strings.CutPrefix(line, "ARG ")
		if !ok {
			continue
		}
		arg = strings.TrimSpace(arg)
		if !strings.Contains(arg, "=") {
			continue
		}

		parts := strings.SplitN(arg, "=", 2)
		key, _, err := lexer.ProcessWord(parts[0], shell.EnvsFromSlice(result))
		if err != nil {
			return nil, fmt.Errorf("processing %q: %w", line, err)
		}

		// Only use the default value if no external arg was provided
		if _, exists := externalArgNames[key]; exists {
			continue
		}

		val, _, err := lexer.ProcessWord(parts[1], shell.EnvsFromSlice(result))
		if err != nil {
			return nil, fmt.Errorf("processing %q: %w", line, err)
		}
		result = append(result, key+"="+val)
	}

	return result, nil
}

// UserFromDockerfile inspects the contents of a provided Dockerfile
// and returns the user that will be used to run the container.
// Optionally accepts build args that may override default values in the Dockerfile.
func UserFromDockerfile(dockerfileContent string, buildArgs ...[]string) (user string, err error) {
	var args []string
	if len(buildArgs) > 0 {
		args = buildArgs[0]
	}

	res, err := parser.Parse(strings.NewReader(dockerfileContent))
	if err != nil {
		return "", fmt.Errorf("parse dockerfile: %w", err)
	}

	resolvedArgs, err := buildArgsWithDefaults(dockerfileContent, args)
	if err != nil {
		return "", err
	}
	lexer := shell.NewLex('\\')

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
		// the image. First, substitute any ARG variables in the image name.
		imageRef := stage.BaseName
		imageRef, _, err := lexer.ProcessWord(imageRef, shell.EnvsFromSlice(resolvedArgs))
		if err != nil {
			return "", fmt.Errorf("processing image ref %q: %w", stage.BaseName, err)
		}

		ref, err := name.ParseReference(strings.TrimSpace(imageRef))
		if err != nil {
			return "", fmt.Errorf("parse image ref %q: %w", imageRef, err)
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
// Optionally accepts build args that may override default values in the Dockerfile.
func ImageFromDockerfile(dockerfileContent string, buildArgs ...[]string) (name.Reference, error) {
	var args []string
	if len(buildArgs) > 0 {
		args = buildArgs[0]
	}

	resolvedArgs, err := buildArgsWithDefaults(dockerfileContent, args)
	if err != nil {
		return nil, err
	}

	// Find the FROM instruction
	var imageRef string
	for _, line := range strings.Split(dockerfileContent, "\n") {
		if fromArgs, ok := strings.CutPrefix(line, "FROM "); ok {
			imageRef = fromArgs
			break
		}
	}
	if imageRef == "" {
		return nil, fmt.Errorf("no FROM directive found")
	}

	lexer := shell.NewLex('\\')
	imageRef, _, err = lexer.ProcessWord(imageRef, shell.EnvsFromSlice(resolvedArgs))
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
