package envbuilder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/executor"
	"github.com/containerd/containerd/platforms"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/sirupsen/logrus"
)

const (
	// WorkspacesDir is the path to the directory where
	// all workspaces are stored by default.
	WorkspacesDir = "/workspaces"

	// EmptyWorkspaceDir is the path to a workspace that has
	// nothing going on... it's empty!
	EmptyWorkspaceDir = WorkspacesDir + "/empty"

	// MagicDir is where all envbuilder related files are stored.
	// This is a special directory that must not be modified
	// by the user or images.
	MagicDir = "envbuilder"
)

type Options struct {
	// InitCommand is the command to run to initialize the workspace.
	// This is ran immediately after the container has been built.
	InitCommand string

	// InitArguments are the arguments to pass to the init command.
	InitArguments []string

	// CacheRepo is the name of the container registry
	// to push the cache image to. If this is empty, the cache
	// will not be pushed.
	CacheRepo string

	// DockerfilePath is a relative path to the workspace
	// folder that will be used to build the workspace.
	// This is an alternative to using a devcontainer
	// that some might find simpler.
	DockerfilePath string

	// FallbackImage is the image to use if no image is
	// specified in the devcontainer.json file and
	// a Dockerfile is not found.
	FallbackImage string

	// Logger is the logger to use for all operations.
	Logger func(format string, args ...interface{})

	// Filesystem is the filesystem to use for all operations.
	// Defaults to the host filesystem.
	Filesystem billy.Filesystem

	// ForceSafe ignores any filesystem safety checks.
	// This could cause serious harm to your system!
	// This is used in cases where bypass is needed
	// to unblock customers!
	ForceSafe bool

	// Insecure bypasses TLS verification when cloning
	// and pulling from container registries.
	Insecure bool

	// RepoURL is the URL of the Git repository to clone.
	// This is optional!
	RepoURL string

	// WorkspaceFolder is the path to the workspace folder
	// that will be built. This is optional!
	WorkspaceFolder string
}

// Run runs the envbuilder.
func Run(ctx context.Context, options Options) error {
	if options.Filesystem == nil {
		options.Filesystem = osfs.New("/")
	}
	if options.WorkspaceFolder == "" {
		var err error
		options.WorkspaceFolder, err = DefaultWorkspaceFolder(options.RepoURL)
		if err != nil {
			return err
		}
	}
	if options.FallbackImage == "" {
		options.FallbackImage = "ubuntu:latest"
	}
	logf := options.Logger

	if options.RepoURL != "" {
		start := time.Now()
		logf("=== Cloning Repository %s to %s...", options.RepoURL, options.WorkspaceFolder)

		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		go func() {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				logf("git: %s", scanner.Text())
			}
		}()

		err := CloneRepo(ctx, CloneRepoOptions{
			Path:     options.WorkspaceFolder,
			Storage:  options.Filesystem,
			RepoURL:  options.RepoURL,
			Insecure: options.Insecure,
			Progress: writer,
		})
		if err != nil {
			return err
		}

		logf("==> Cloned Repository in %s", time.Since(start))
	}

	var buildParams *BuildParameters

	defaultBuildParams := func() error {
		dockerfile := filepath.Join(MagicDir, "Dockerfile")
		file, err := options.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.Write([]byte("FROM " + options.FallbackImage))
		if err != nil {
			return err
		}
		buildParams = &BuildParameters{
			DockerfilePath: dockerfile,
			BuildContext:   MagicDir,
		}
		return nil
	}

	if options.DockerfilePath == "" {
		// Only look for a devcontainer if a Dockerfile wasn't specified.
		// devcontainer is a standard, so it's reasonable to be the default.
		devcontainerDir := filepath.Join(options.WorkspaceFolder, ".devcontainer")
		devcontainerPath := filepath.Join(devcontainerDir, "devcontainer.json")
		_, err := options.Filesystem.Stat(devcontainerPath)
		if err == nil {
			// We know a devcontainer exists.
			// Let's parse it and use it!
			file, err := options.Filesystem.Open(devcontainerPath)
			if err != nil {
				return fmt.Errorf("open devcontainer.json: %w", err)
			}
			defer file.Close()
			content, err := io.ReadAll(file)
			if err != nil {
				return fmt.Errorf("read devcontainer.json: %w", err)
			}
			devContainer, err := ParseDevcontainer(content)
			if err != nil {
				return fmt.Errorf("parse devcontainer.json: %w", err)
			}
			buildParams, err = devContainer.Compile(options.Filesystem, devcontainerDir, MagicDir)
			if err != nil {
				return fmt.Errorf("compile devcontainer.json: %w", err)
			}
		}
	} else {
		// If a Dockerfile was specified, we use that.
		dockerfilePath := filepath.Join(options.WorkspaceFolder, options.DockerfilePath)
		_, err := options.Filesystem.Stat(dockerfilePath)
		if err == nil {
			buildParams = &BuildParameters{
				DockerfilePath: dockerfilePath,
				BuildContext:   options.WorkspaceFolder,
				Cache:          true,
			}
		}
	}

	if buildParams == nil {
		// If there isn't a devcontainer.json file in the repository,
		// we fallback to whatever the `DefaultImage` is.
		err := defaultBuildParams()
		if err != nil {
			return err
		}
	}

	HijackLogrus(func(entry *logrus.Entry) {
		logf("builder: %s", entry.Message)
	})
	// At this point we have all the context, we can now build!
	image, err := executor.DoBuild(&config.KanikoOptions{
		// Boilerplate!
		CustomPlatform:    platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
		SnapshotMode:      "redo",
		RunV2:             true,
		Destinations:      []string{"local"},
		CacheRunLayers:    true,
		CacheCopyLayers:   true,
		CompressedCaching: true,
		CacheOptions: config.CacheOptions{
			// Cache for a week by default!
			CacheTTL: time.Hour * 24 * 7,
		},

		BuildArgs:      buildParams.BuildArgs,
		CacheRepo:      options.CacheRepo,
		Cache:          buildParams.Cache && options.CacheRepo != "",
		DockerfilePath: buildParams.DockerfilePath,
		RegistryOptions: config.RegistryOptions{
			Insecure:      options.Insecure,
			InsecurePull:  options.Insecure,
			SkipTLSVerify: options.Insecure,
		},
		SrcContext: buildParams.BuildContext,
	})
	if err != nil {
		return fmt.Errorf("build with kaniko: %w", err)
	}

	configFile, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("get image config: %w", err)
	}

	username := configFile.Config.User
	if buildParams.User != "" {
		username = buildParams.User
	}
	if username == "" {
		logf("no user specified, using root")
	}
	user, err := findUser(username)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return fmt.Errorf("parse uid: %w", err)
	}
	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return fmt.Errorf("parse gid: %w", err)
	}

	// It must be set in this parent process otherwise nothing will be found!
	for _, env := range configFile.Config.Env {
		pair := strings.SplitN(env, "=", 2)
		os.Setenv(pair[0], pair[1])
	}
	for _, env := range buildParams.Env {
		pair := strings.SplitN(env, "=", 2)
		os.Setenv(pair[0], pair[1])
	}

	sysProcAttr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}

	logf("=== Starting init command as the %q user...", user.Username)
	cmd := exec.CommandContext(ctx, options.InitCommand, options.InitArguments...)
	cmd.Env = os.Environ()
	cmd.Dir = options.WorkspaceFolder
	cmd.SysProcAttr = sysProcAttr

	var buf bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(&buf)
		for scanner.Scan() {
			logf("[%s, %+v]: %s", options.InitCommand, options.InitArguments, scanner.Text())
		}
	}()
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	return cmd.Run()
}

// DefaultWorkspaceFolder returns the default workspace folder
// for a given repository URL.
func DefaultWorkspaceFolder(repoURL string) (string, error) {
	if repoURL == "" {
		return "/workspaces/empty", nil
	}
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", err
	}
	name := strings.Split(parsed.Path, "/")
	return fmt.Sprintf("/workspaces/%s", name[len(name)-1]), nil
}

type BuildParameters struct {
	DockerfilePath string
	BuildContext   string
	BuildArgs      []string
	Cache          bool

	User string
	Env  []string
}

// findUser looks up a user by name or ID.
func findUser(nameOrID string) (*user.User, error) {
	if nameOrID == "" {
		return &user.User{
			Uid: "0",
			Gid: "0",
		}, nil
	}
	_, err := strconv.Atoi(nameOrID)
	if err == nil {
		return user.LookupId(nameOrID)
	}
	return user.Lookup(nameOrID)
}

// SystemOptions returns a set of options from environment variables.
func SystemOptions(getEnv func(string) string) Options {
	options := Options{}

	initScript := getEnv("INIT_SCRIPT")
	if initScript != "" {
		options.InitCommand = "/bin/sh"
		options.InitArguments = []string{"-c", initScript}
	}

	cacheRepo := getEnv("CACHE_REPO")
	if cacheRepo != "" {
		options.CacheRepo = cacheRepo
	}

	dockerfilePath := getEnv("DOCKERFILE_PATH")
	if dockerfilePath != "" {
		options.DockerfilePath = dockerfilePath
	}

	fallbackImage := getEnv("FALLBACK_IMAGE")
	if fallbackImage != "" {
		options.FallbackImage = fallbackImage
	}

	forceSafe := getEnv("FORCE_SAFE")
	if forceSafe != "" {
		options.ForceSafe = true
	}

	insecure := getEnv("INSECURE")
	if insecure != "" {
		options.Insecure = true
	}

	repoURL := getEnv("REPO_URL")
	if repoURL != "" {
		options.RepoURL = repoURL
	}

	workspaceFolder := getEnv("WORKSPACE_FOLDER")
	if workspaceFolder != "" {
		options.WorkspaceFolder = workspaceFolder
	}

	return options
}
