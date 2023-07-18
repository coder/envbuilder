package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/gittest"
	"github.com/coder/envbuilder/registrytest"
	clitypes "github.com/docker/cli/cli/config/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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
	_, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + url,
	}})
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
	_, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + url,
		"DOCKERFILE_PATH=Dockerfile",
		"GIT_USERNAME=kyle",
		"GIT_PASSWORD=testing",
	}})
	require.NoError(t, err)
}

func TestBuildFromDevcontainerWithFeatures(t *testing.T) {
	t.Parallel()

	registry := registrytest.New(t)
	ref := registrytest.WriteContainer(t, registry, "coder/test:latest", features.TarLayerMediaType, map[string]any{
		"devcontainer-feature.json": &features.Spec{
			ID:      "test",
			Name:    "test",
			Version: "1.0.0",
			Options: map[string]features.Option{
				"bananas": {
					Type: "string",
				},
			},
		},
		"install.sh": "echo $BANANAS > /test",
	})

	// Ensures that a Git repository with a devcontainer.json is cloned and built.
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			".devcontainer/devcontainer.json": `{
				"name": "Test",
				"build": {
					"dockerfile": "Dockerfile"
				},
				"features": {
					"` + ref + `": {
						"bananas": "hello"
					}
				}
			}`,
			".devcontainer/Dockerfile": "FROM ubuntu",
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + url,
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /test")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildFromDockerfile(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + url,
		"DOCKERFILE_PATH=Dockerfile",
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildIgnoreVarRunSecrets(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
	})
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "secret"), []byte("test"), 0644)
	require.NoError(t, err)
	ctr, err := runEnvbuilder(t, options{
		env: []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
		},
		binds: []string{fmt.Sprintf("%s:/var/run/secrets", dir)},
	})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildWithSetupScript(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + url,
		"DOCKERFILE_PATH=Dockerfile",
		"SETUP_SCRIPT=echo \"INIT_ARGS=-c 'echo hi > /wow && sleep infinity'\" >> $ENVBUILDER_ENV",
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "cat /wow")
	require.Equal(t, "hi", strings.TrimSpace(output))
}

func TestBuildCustomCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(createGitHandler(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
	}))
	ctr, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + srv.URL,
		"DOCKERFILE_PATH=Dockerfile",
		"SSL_CERT_BASE64=" + base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: srv.TLS.Certificates[0].Certificate[0],
		})),
	}})
	require.NoError(t, err)

	output := execContainer(t, ctr, "echo hello")
	require.Equal(t, "hello", strings.TrimSpace(output))
}

func TestBuildStopStartCached(t *testing.T) {
	// Ensures that a Git repository with a Dockerfile is cloned and built.
	url := createGitServer(t, gitServerOptions{
		files: map[string]string{
			"Dockerfile": "FROM alpine:latest",
		},
	})
	ctr, err := runEnvbuilder(t, options{env: []string{
		"GIT_URL=" + url,
		"DOCKERFILE_PATH=Dockerfile",
		"SKIP_REBUILD=true",
	}})
	require.NoError(t, err)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()

	ctx := context.Background()
	err = cli.ContainerStop(ctx, ctr, container.StopOptions{})
	require.NoError(t, err)

	err = cli.ContainerStart(ctx, ctr, types.ContainerStartOptions{})
	require.NoError(t, err)

	logChan, _ := streamContainerLogs(t, cli, ctr)
	for {
		log := <-logChan
		if strings.Contains(log, "Skipping build because of cache") {
			break
		}
	}
}

func TestCloneFailsFallback(t *testing.T) {
	t.Parallel()
	t.Run("BadRepo", func(t *testing.T) {
		t.Parallel()
		_, err := runEnvbuilder(t, options{env: []string{
			"GIT_URL=bad-value",
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
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
		_, err := runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
		require.ErrorContains(t, err, "dockerfile parse error")
	})
	t.Run("FailsBuild", func(t *testing.T) {
		t.Parallel()
		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": `FROM alpine
RUN exit 1`,
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
		}})
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
		_, err := runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
		}})
		require.ErrorContains(t, err, envbuilder.ErrNoFallbackImage.Error())
	})
	t.Run("NoImageOrDockerfile", func(t *testing.T) {
		t.Parallel()
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				".devcontainer/devcontainer.json": "{}",
			},
		})
		ctr, err := runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
			"FALLBACK_IMAGE=alpine:latest",
		}})
		require.NoError(t, err)

		output := execContainer(t, ctr, "echo hello")
		require.Equal(t, "hello", strings.TrimSpace(output))
	})
}

func TestPrivateRegistry(t *testing.T) {
	t.Parallel()
	t.Run("NoAuth", func(t *testing.T) {
		t.Parallel()
		image := setupPassthroughRegistry(t, "library/alpine", &registryAuth{
			Username: "user",
			Password: "test",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		_, err := runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
		}})
		require.ErrorContains(t, err, "Unauthorized")
	})
	t.Run("Auth", func(t *testing.T) {
		t.Parallel()
		image := setupPassthroughRegistry(t, "library/alpine", &registryAuth{
			Username: "user",
			Password: "test",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		config, err := json.Marshal(envbuilder.DockerConfig{
			AuthConfigs: map[string]clitypes.AuthConfig{
				image: {
					Username: "user",
					Password: "test",
				},
			},
		})
		require.NoError(t, err)

		_, err = runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
			"DOCKER_CONFIG_BASE64=" + base64.StdEncoding.EncodeToString(config),
		}})
		require.NoError(t, err)
	})
	t.Run("InvalidAuth", func(t *testing.T) {
		t.Parallel()
		image := setupPassthroughRegistry(t, "library/alpine", &registryAuth{
			Username: "user",
			Password: "banana",
		})

		// Ensures that a Git repository with a Dockerfile is cloned and built.
		url := createGitServer(t, gitServerOptions{
			files: map[string]string{
				"Dockerfile": "FROM " + image,
			},
		})
		config, err := json.Marshal(envbuilder.DockerConfig{
			AuthConfigs: map[string]clitypes.AuthConfig{
				image: {
					Username: "user",
					Password: "wrong",
				},
			},
		})
		require.NoError(t, err)

		_, err = runEnvbuilder(t, options{env: []string{
			"GIT_URL=" + url,
			"DOCKERFILE_PATH=Dockerfile",
			"DOCKER_CONFIG_BASE64=" + base64.StdEncoding.EncodeToString(config),
		}})
		require.ErrorContains(t, err, "Unauthorized")
	})
}

type registryAuth struct {
	Username string
	Password string
}

func setupPassthroughRegistry(t *testing.T, image string, auth *registryAuth) string {
	t.Helper()
	dockerURL, err := url.Parse("https://registry-1.docker.io")
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(dockerURL)

	// The Docker registry uses short-lived JWTs to authenticate
	// anonymously to pull images. To test our MITM auth, we need to
	// generate a JWT for the proxy to use.
	registry, err := name.NewRegistry("registry-1.docker.io")
	require.NoError(t, err)
	proxy.Transport, err = transport.NewWithContext(context.Background(), registry, authn.Anonymous, http.DefaultTransport, []string{})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "registry-1.docker.io"
		r.URL.Host = "registry-1.docker.io"
		r.URL.Scheme = "https"

		if auth != nil {
			user, pass, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Access to the staging site\", charset=\"UTF-8\"")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if user != auth.Username || pass != auth.Password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		proxy.ServeHTTP(w, r)

	}))
	return fmt.Sprintf("%s/%s", strings.TrimPrefix(srv.URL, "http://"), image)
}

func TestNoMethodFails(t *testing.T) {
	_, err := runEnvbuilder(t, options{env: []string{}})
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
	srv := httptest.NewServer(createGitHandler(t, opts))
	return srv.URL
}

func createGitHandler(t *testing.T, opts gitServerOptions) http.Handler {
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opts.username != "" || opts.password != "" {
			username, password, ok := r.BasicAuth()
			if !ok || username != opts.username || password != opts.password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		gittest.NewServer(fs).ServeHTTP(w, r)
	})
}

// cleanOldEnvbuilders removes any old envbuilder containers.
func cleanOldEnvbuilders() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
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

type options struct {
	binds []string
	env   []string
}

// runEnvbuilder starts the envbuilder container with the given environment
// variables and returns the container ID.
func runEnvbuilder(t *testing.T, options options) (string, error) {
	t.Helper()
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	t.Cleanup(func() {
		cli.Close()
	})
	ctr, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "envbuilder:latest",
		Env:   options.env,
		Labels: map[string]string{
			testContainerLabel: "true",
		},
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode("host"),
		Binds:       options.binds,
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

	logChan, errChan := streamContainerLogs(t, cli, ctr.ID)
	go func() {
		for log := range logChan {
			if strings.HasPrefix(log, "=== Running the init command") {
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

func streamContainerLogs(t *testing.T, cli *client.Client, containerID string) (chan string, chan error) {
	ctx := context.Background()
	err := cli.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
	require.NoError(t, err)
	rawLogs, err := cli.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: false,
	})
	require.NoError(t, err)

	logChan := make(chan string, 32)
	errChan := make(chan error, 1)

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

			logChan <- scanner.Text()
		}
	}()

	return logChan, errChan
}
