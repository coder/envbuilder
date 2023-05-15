package envbuilder

import (
	"os"
	"path/filepath"

	"github.com/go-git/go-billy/v5"
	"muzzammil.xyz/jsonc"
)

// ParseDevcontainer parses a devcontainer.json file.
func ParseDevcontainer(content []byte) (*DevContainer, error) {
	content = jsonc.ToJSON(content)
	var schema DevContainer
	return &schema, jsonc.Unmarshal(content, &schema)
}

type DevContainer struct {
	Image      string            `json:"image"`
	Build      DevContainerBuild `json:"build"`
	RemoteUser string            `json:"remoteUser"`
	RemoteEnv  map[string]string `json:"remoteEnv"`

	// Deprecated but still frequently used...
	Dockerfile string `json:"dockerFile"`
	Context    string `json:"context"`
}

type DevContainerBuild struct {
	Dockerfile string            `json:"dockerfile"`
	Context    string            `json:"context"`
	Args       map[string]string `json:"args"`
	Target     string            `json:"target"`
	CacheFrom  string            `json:"cache_from"`
}

// Compile returns the build parameters for the workspace.
// devcontainerDir is the path to the directory where the devcontainer.json file
// is located. scratchDir is the path to the directory where the Dockerfile will
// be written to if one doesn't exist.
func (d *DevContainer) Compile(fs billy.Filesystem, devcontainerDir, scratchDir string) (*BuildParameters, error) {
	env := make([]string, 0)
	for key, value := range d.RemoteEnv {
		env = append(env, key+"="+value)
	}
	params := &BuildParameters{
		User: d.RemoteUser,
		Env:  env,
	}

	if d.Image != "" {
		// We just write the image to a file and return it.
		dockerfilePath := filepath.Join(scratchDir, "Dockerfile")
		file, err := fs.OpenFile(dockerfilePath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		_, err = file.Write([]byte("FROM " + d.Image))
		if err != nil {
			return nil, err
		}
		params.DockerfilePath = dockerfilePath
		params.BuildContext = scratchDir
		return params, nil
	}
	buildArgs := make([]string, 0)
	for key, value := range d.Build.Args {
		buildArgs = append(buildArgs, key+"="+value)
	}
	params.BuildArgs = buildArgs
	params.Cache = true

	// Deprecated values!
	if d.Dockerfile != "" {
		d.Build.Dockerfile = d.Dockerfile
	}
	if d.Context != "" {
		d.Build.Context = d.Context
	}

	params.DockerfilePath = filepath.Join(devcontainerDir, d.Build.Dockerfile)
	params.BuildContext = filepath.Join(devcontainerDir, d.Build.Context)
	return params, nil
}
