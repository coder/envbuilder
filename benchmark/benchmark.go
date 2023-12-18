package benchmark

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

//go:embed images
var dirs embed.FS

// ImageNames returns the list of embedded images.
func ImageNames() ([]string, error) {
	entries, err := dirs.ReadDir("images")
	if err != nil {
		return nil, err
	}
	var result []string
	for _, entry := range entries {
		if entry.IsDir() {
			result = append(result, entry.Name())
		}
	}
	return result, nil
}

// Image returns the image with the given name.
func Image(ctx context.Context, name, cacheDir string) (v1.Image, error) {
	tarPath, err := Build(ctx, name, cacheDir)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	image, err := tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		return nil, fmt.Errorf("image from path: %w", err)
	}
	return image, nil
}

// Build returns the path to a tar file containing the built image.
// This is to be served by a registry for consumption when benchmarking.
// The result may be returned immediately if the sha256 hashed contents
// of the path already exist in the cache directory.
func Build(ctx context.Context, name string, cacheDir string) (string, error) {
	entries, err := dirs.ReadDir(filepath.Join("images", name))
	if err != nil {
		return "", fmt.Errorf("read dir: %w", err)
	}
	hash := sha256.New()
	var tarBuf bytes.Buffer
	tarWtr := tar.NewWriter(&tarBuf)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := dirs.ReadFile(filepath.Join("images", name, entry.Name()))
		if err != nil {
			return "", fmt.Errorf("read file: %w", err)
		}
		_, err = hash.Write(content)
		if err != nil {
			return "", fmt.Errorf("write hash: %w", err)
		}
		err = tarWtr.WriteHeader(&tar.Header{
			Name:     entry.Name(),
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		})
		if err != nil {
			return "", fmt.Errorf("write header: %w", err)
		}
		_, err = tarWtr.Write(content)
		if err != nil {
			return "", fmt.Errorf("write content: %w", err)
		}
	}
	hashed := fmt.Sprintf("%x", hash.Sum(nil))
	imageName := "envbuilder-bench-" + name
	cachePath := filepath.Join(cacheDir, hashed) + ".tar"
	_, err = os.Stat(cachePath)
	if err == nil {
		return cachePath, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat cache path: %w", err)
	}

	client, err := dockerClient()
	if err != nil {
		return "", fmt.Errorf("docker client: %w", err)
	}
	defer client.Close()

	resp, err := client.ImageBuild(ctx, &tarBuf, types.ImageBuildOptions{
		Tags: []string{imageName},
	})
	if err != nil {
		return "", fmt.Errorf("image build: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("close body: %w", err)
	}
	err = os.MkdirAll(cacheDir, 0755)
	if err != nil {
		return "", fmt.Errorf("mkdir cache dir: %w", err)
	}
	imageTar, err := os.OpenFile(cachePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return "", fmt.Errorf("open cache path: %w", err)
	}
	defer imageTar.Close()
	imageSaver, err := client.ImageSave(ctx, []string{imageName})
	if err != nil {
		return "", fmt.Errorf("image save: %w", err)
	}
	_, err = io.Copy(imageTar, imageSaver)
	if err != nil {
		return "", fmt.Errorf("copy image saver: %w", err)
	}
	return cachePath, nil
}

func dockerClient() (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
}
