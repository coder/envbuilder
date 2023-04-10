package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/gittest"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testContainerLabel = "envbox-integration-test"
)

func TestFailsGitAuth(t *testing.T) {
	t.Parallel()
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
		username: "kyle",
		password: "testing",
	})
	_, err := runEnvbuilder(t, []string{
		"GIT_URL=" + url,
	})
	require.ErrorContains(t, err, "authentication required")
}

func TestSucceedsGitAuth(t *testing.T) {
	t.Parallel()
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
		username: "kyle",
		password: "testing",
	})
	_, err := runEnvbuilder(t, []string{
		"GIT_URL=" + url,
		"DOCKERFILE_PATH=Dockerfile",
		"GIT_USERNAME=kyle",
		"GIT_PASSWORD=testing",
	})
	require.NoError(t, err)
}

func TestBuildFromDockerfile(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
	})
	ctr, err := runEnvbuilder(t, []string{
		"GIT_URL=" + url,
		"DOCKERFILE_PATH=Dockerfile",
	})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildFailsFallback(t *testing.T) {
	t.Parallel()
	t.Run("BadDockerfile", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "bad syntax",
			},
		})
		_, err := runEnvbuilder(t, []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
		})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
	t.Run("BadDevcontainer", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				".devcontainer/devcontainer.json": "not json",
			},
		})
		_, err := runEnvbuilder(t, []string{
			"GIT_URL=" + url,
		})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
}

func TestPrivateRegistry(t *testing.T) {
	t.Parallel()
	t.Run("NoAuth", func(t *testing.T) {
		t.Parallel()
		image := setupPassthroughRegistry(t, "library/alpine")

		fmt.Printf("IMAGE %s\n", image)
		time.Sleep(time.Hour)

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		_, err := runEnvbuilder(t, []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
		})
		require.NoError(t, err)
	})
}

func setupPassthroughRegistry(t *testing.T, image string) string {
	t.Helper()
	dockerURL, err := url.Parse("https://registry-1.docker.io")
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(dockerURL)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "registry-1.docker.io"
		r.URL.Host = "registry-1.docker.io"
		r.URL.Scheme = "https"

		proxy.ServeHTTP(w, r)
	}))
	return fmt.Sprintf("%s/%s", strings.TrimPrefix(srv.URL, "http://"), image)
}

func TestNoMethodFails(t *testing.T) {
	_, err := runEnvbuilder(t, []string{})
	require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
}

// TestMain runs before all tests to build the envbuilder image.
func TestMain(m *testing.M) {
	cleanOldEnvbuilders()
	ctx := context.Background()
	// Run the build script to create the envbuilder image.
	cmd := exec.CommandContext(ctx, "../scripts/build.sh")
	rdr, wtr := io.Pipe()
	defer rdr.Close()
	defer wtr.Close()
	cmd.Stdout = wtr
	cmd.Stderr = wtr
	go func() {
		scanner := bufio.NewScanner(rdr)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()
	err := cmd.Run()
	if err != nil {
		panic(err)
	}

	m.Run()
}

type gitServerOptions struct {
	files    map[string]string
	username string
	password string
}

// createGitServer creates a git repository with an in-memory filesystem
// and serves it over HTTP using a httptest.Server.
func createGitServer(t *testing.T, opts gitServerOptions) string {
	t.Helper()
	fs := memfs.New()
	repo := gittest.NewRepo(t, fs)
	w, err := repo.Worktree()
	require.NoError(t, err)
	for key, value := range opts.files {
		gittest.WriteFile(t, fs, key, value)
		_, err = w.Add(key)
		require.NoError(t, err)
	}
	commit, err := w.Commit("my test commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Example",
			Email: "in@tests.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)
	_, err = repo.CommitObject(commit)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opts.username != "" || opts.password != "" {
			username, password, ok := r.BasicAuth()
			if !ok || username != opts.username || password != opts.password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		gittest.NewServer(fs).ServeHTTP(w, r)
	}))
	return srv.URL
}

// cleanOldEnvbuilders removes any old envbuilder containers.
func cleanOldEnvbuilders() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	defer cli.Close()
	ctrs, err := cli.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "label",
			Value: testContainerLabel,
		}),
	})
	if err != nil {
		panic(err)
	}
	for _, ctr := range ctrs {
		cli.ContainerRemove(ctx, ctr.ID, types.ContainerRemoveOptions{
			Force: true,
		})
	}
}

// runEnvbuilder starts the envbuilder container with the given environment
// variables and returns the container ID.
func runEnvbuilder(t *testing.T, env []string) (string, error) {
	t.Helper()
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(t, err)
	t.Cleanup(func() {
		cli.Close()
	})
	ctr, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "envbuilder:latest",
		Env:   env,
		Labels: map[string]string{
			testContainerLabel: "true",
		},
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode("host"),
	}, nil, nil, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		cli.ContainerRemove(ctx, ctr.ID, types.ContainerRemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		})
	})
	err = cli.ContainerStart(ctx, ctr.ID, types.ContainerStartOptions{})
	require.NoError(t, err)
	rawLogs, err := cli.ContainerLogs(ctx, ctr.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: false,
	})
	require.NoError(t, err)
	errChan := make(chan error)

	logsReader, logsWriter := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(logsWriter, logsWriter, rawLogs)
		assert.NoError(t, err)
		_ = logsReader.Close()
		_ = logsWriter.Close()
	}()
	go func() {
		defer close(errChan)
		scanner := bufio.NewScanner(logsReader)
		for scanner.Scan() {
			t.Logf("%q", strings.TrimSpace(scanner.Text()))
			if strings.HasPrefix(scanner.Text(), "error: ") {
				errChan <- errors.New(scanner.Text())
				return
			}
			if strings.HasPrefix(scanner.Text(), "=== Running the init command") {
				errChan <- nil
				return
			}
		}
	}()

	return ctr.ID, <-errChan
}

// execContainer executes the given command in the given container and returns
// the output.
func execContainer(t *testing.T, containerID, command string) string {
	t.Helper()
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()
	execConfig := types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{"/bin/sh", "-c", command},
	}
	execID, err := cli.ContainerExecCreate(ctx, containerID, execConfig)
	require.NoError(t, err)
	resp, err := cli.ContainerExecAttach(ctx, execID.ID, types.ExecStartCheck{})
	require.NoError(t, err)
	defer resp.Close()
	var buf bytes.Buffer
	_, err = stdcopy.StdCopy(&buf, &buf, resp.Reader)
	require.NoError(t, err)
	return buf.String()
}
