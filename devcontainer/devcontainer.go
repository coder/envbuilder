package devcontainer

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/GoogleContainerTools/kaniko/pkg/creds"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/go-git/go-billy/v5"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"muzzammil.xyz/jsonc"
)

// Parse parses a devcontainer.json file.
func Parse(content []byte) (*Spec, error) {
	content = jsonc.ToJSON(content)
	var schema Spec
	return &schema, jsonc.Unmarshal(content, &schema)
}

type Spec struct {
	Image      string            `json:"image"`
	Build      BuildSpec         `json:"build"`
	RemoteUser string            `json:"remoteUser"`
	RemoteEnv  map[string]string `json:"remoteEnv"`
	// Features is a map of feature names to feature configurations.
	Features map[string]map[string]any `json:"features"`

	// Deprecated but still frequently used...
	Dockerfile string `json:"dockerFile"`
	Context    string `json:"context"`
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
	BuildArgs         []string

	User string
	Env  []string
}

// Compile returns the build parameters for the workspace.
// devcontainerDir is the path to the directory where the devcontainer.json file
// is located. scratchDir is the path to the directory where the Dockerfile will
// be written to if one doesn't exist.
func (s *Spec) Compile(fs billy.Filesystem, devcontainerDir, scratchDir string) (*Compiled, error) {
	env := make([]string, 0)
	for key, value := range s.RemoteEnv {
		env = append(env, key+"="+value)
	}
	params := &Compiled{
		User: s.RemoteUser,
		Env:  env,
	}

	if s.Image != "" {
		// We just write the image to a file and return it.
		dockerfilePath := filepath.Join(scratchDir, "Dockerfile")
		file, err := fs.OpenFile(dockerfilePath, os.O_CREATE|os.O_WRONLY, 0644)
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

		params.DockerfilePath = filepath.Join(devcontainerDir, s.Build.Dockerfile)
		params.BuildContext = filepath.Join(devcontainerDir, s.Build.Context)
	}
	buildArgs := make([]string, 0)
	for key, value := range s.Build.Args {
		buildArgs = append(buildArgs, key+"="+value)
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
		params.User = UserFromDockerfile(params.DockerfileContent)
	}
	if params.User == "" {
		image := ImageFromDockerfile(params.DockerfileContent)
		imageRef, err := name.ParseReference(image)
		if err != nil {
			return nil, fmt.Errorf("parse image from dockerfile %q: %w", image, err)
		}
		params.User, err = UserFromImage(imageRef)
		if err != nil {
			return nil, fmt.Errorf("get user from image %q: %w", image, err)
		}
	}
	params.DockerfileContent, err = s.compileFeatures(fs, scratchDir, params.User, params.DockerfileContent)
	if err != nil {
		return nil, err
	}
	return params, nil
}

func (s *Spec) compileFeatures(fs billy.Filesystem, scratchDir, remoteUser, dockerfileContent string) (string, error) {
	// If there are no features, we don't need to do anything!
	if len(s.Features) == 0 {
		return dockerfileContent, nil
	}

	featuresDir := filepath.Join(scratchDir, "features")
	err := fs.MkdirAll(featuresDir, 0644)
	if err != nil {
		return "", fmt.Errorf("create features directory: %w", err)
	}
	featureDirectives := []string{}
	for featureRef, featureOpts := range s.Features {
		// It's important for caching that this directory is static.
		// If it changes on each run then the container will not be cached.
		//
		// devcontainers/cli has a very complex method of computing the feature
		// name from the feature reference. We're just going to hash it for simplicity.
		featureSha := md5.Sum([]byte(featureRef))
		featureName := strings.Split(filepath.Base(featureRef), ":")[0]
		featureDir := filepath.Join(featuresDir, fmt.Sprintf("%s-%x", featureName, featureSha[:4]))
		err = fs.MkdirAll(featureDir, 0644)
		if err != nil {
			return "", err
		}
		spec, err := features.Extract(fs, featureDir, featureRef)
		if err != nil {
			return "", fmt.Errorf("extract feature %s: %w", featureRef, err)
		}
		directive, err := spec.Compile(featureOpts)
		if err != nil {
			return "", fmt.Errorf("compile feature %s: %w", featureRef, err)
		}
		featureDirectives = append(featureDirectives, directive)
	}

	lines := []string{"\nUSER root"}
	lines = append(lines, featureDirectives...)
	if remoteUser != "" {
		// TODO: We should warn that because we were unable to find the remote user,
		// we're going to run as root.
		lines = append(lines, fmt.Sprintf("USER %s", remoteUser))
	}
	return strings.Join(append([]string{dockerfileContent}, lines...), "\n"), err
}

// UserFromDockerfile inspects the contents of a provided Dockerfile
// and returns the user that will be used to run the container.
func UserFromDockerfile(dockerfileContent string) string {
	lines := strings.Split(dockerfileContent, "\n")
	// Iterate over lines in reverse
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !strings.HasPrefix(line, "USER ") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "USER "))
	}
	return ""
}

// ImageFromDockerfile inspects the contents of a provided Dockerfile
// and returns the image that will be used to run the container.
func ImageFromDockerfile(dockerfileContent string) string {
	lines := strings.Split(dockerfileContent, "\n")
	// Iterate over lines in reverse
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !strings.HasPrefix(line, "FROM ") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "FROM "))
	}
	return ""
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
