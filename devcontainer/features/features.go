package features

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Extract unpacks the feature from the image and returns the
// parsed specification.
func Extract(fs billy.Filesystem, directory, reference string) (*Spec, error) {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("parse feature ref %s: %w", reference, err)
	}
	image, err := remote.Image(ref)
	if err != nil {
		return nil, fmt.Errorf("fetch feature image %s: %w", reference, err)
	}
	manifest, err := image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("fetch feature manifest %s: %w", reference, err)
	}

	var tarLayer *tar.Reader
	for _, manifestLayer := range manifest.Layers {
		if manifestLayer.MediaType != TarLayerMediaType {
			continue
		}
		layer, err := image.LayerByDigest(manifestLayer.Digest)
		if err != nil {
			return nil, fmt.Errorf("fetch feature layer %s: %w", reference, err)
		}
		layerReader, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("uncompress feature layer %s: %w", reference, err)
		}
		tarLayer = tar.NewReader(layerReader)
		break
	}
	if tarLayer == nil {
		return nil, fmt.Errorf("no tar layer found with media type %q: are you sure this is a devcontainer feature?", TarLayerMediaType)
	}

	for {
		header, err := tarLayer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read feature layer %s: %w", reference, err)
		}
		path := filepath.Join(directory, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			err = fs.MkdirAll(path, 0755)
			if err != nil {
				return nil, fmt.Errorf("mkdir %s: %w", path, err)
			}
		case tar.TypeReg:
			outFile, err := fs.Create(path)
			if err != nil {
				return nil, fmt.Errorf("create %s: %w", path, err)
			}
			_, err = io.Copy(outFile, tarLayer)
			if err != nil {
				return nil, fmt.Errorf("copy %s: %w", path, err)
			}
			err = outFile.Close()
			if err != nil {
				return nil, fmt.Errorf("close %s: %w", path, err)
			}
		default:
			return nil, fmt.Errorf("unknown type %d in %s", header.Typeflag, path)
		}
	}

	installScriptPath := filepath.Join(directory, "install.sh")
	_, err = fs.Stat(installScriptPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("install.sh must be in the root of the feature")
		}
		return nil, fmt.Errorf("stat install.sh: %w", err)
	}
	err = os.Chmod(installScriptPath, 0755)
	if err != nil {
		return nil, fmt.Errorf("chmod install.sh: %w", err)
	}

	featureFile, err := fs.Open(filepath.Join(directory, "devcontainer-feature.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("devcontainer-feature.json must be in the root of the feature")
		}
		return nil, fmt.Errorf("open devcontainer-feature.json: %w", err)
	}
	defer featureFile.Close()
	var spec *Spec
	err = json.NewDecoder(featureFile).Decode(&spec)
	if err != nil {
		return nil, fmt.Errorf("decode devcontainer-feature.json: %w", err)
	}
	// See https://containers.dev/implementors/features/#devcontainer-feature-json-properties
	if spec.ID == "" {
		return nil, errors.New(`devcontainer-feature.json: id is required`)
	}
	if spec.Version == "" {
		return nil, errors.New(`devcontainer-feature.json: version is required`)
	}
	if spec.Name == "" {
		return nil, errors.New(`devcontainer-feature.json: name is required`)
	}

	spec.InstallScriptPath = installScriptPath
	return spec, nil
}

const (
	TarLayerMediaType = "application/vnd.devcontainers.layer.v1+tar"
)

type Option struct {
	Type        string   `json:"type"` // "boolean" or "string"
	Proposals   []string `json:"proposals"`
	Enum        []string `json:"enum"`
	Default     any      `json:"default"` // boolean or string
	Description string   `json:"description"`
}

type Spec struct {
	ID               string            `json:"id"`
	Version          string            `json:"version"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	DocumentationURL string            `json:"documentationURL"`
	LicenseURL       string            `json:"licenseURL"`
	Keywords         []string          `json:"keywords"`
	Options          map[string]Option `json:"options"`
	ContainerEnv     map[string]string `json:"containerEnv"`

	InstallScriptPath string `json:"-"`
}

// Extract unpacks the feature from the image and returns a set of lines
// that should be appended to a Dockerfile to install the feature.
func (s *Spec) Compile(options map[string]any) (string, error) {
	// See https://containers.dev/implementors/features/#invoking-installsh
	runDirective := []string{"RUN"}
	for key, value := range s.Options {
		strValue := fmt.Sprintf("%v", value.Default)
		provided, ok := options[key]
		if ok {
			strValue = fmt.Sprintf("%v", provided)
			// delete so we can check if there are any unknown options
			delete(options, key)
		}
		runDirective = append(runDirective, fmt.Sprintf("%s=%s", convertOptionNameToEnv(key), strValue))
	}
	if len(options) > 0 {
		return "", fmt.Errorf("unknown option: %v", options)
	}
	runDirective = append(runDirective, s.InstallScriptPath)

	// Prefix and suffix with a newline to ensure the RUN command is on its own line.
	lines := []string{"\n"}
	for key, value := range s.ContainerEnv {
		lines = append(lines, fmt.Sprintf("ENV %s=%s", key, value))
	}
	lines = append(lines, strings.Join(runDirective, " "), "\n")

	return strings.Join(lines, "\n"), nil
}

var (
	matchNonWords                   = regexp.MustCompile(`/[^\w_]/g`)
	matchPrefixDigitsAndUnderscores = regexp.MustCompile(`/^[\d_]+/g`)
)

// See https://containers.dev/implementors/features/#option-resolution
func convertOptionNameToEnv(optionName string) string {
	optionName = matchNonWords.ReplaceAllString(optionName, "_")
	optionName = matchPrefixDigitsAndUnderscores.ReplaceAllString(optionName, "")
	return strings.ToUpper(optionName)
}
