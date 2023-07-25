package envbuilder

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/kballard/go-shellquote"
	"github.com/mattn/go-isatty"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/creds"
	"github.com/GoogleContainerTools/kaniko/pkg/executor"
	"github.com/GoogleContainerTools/kaniko/pkg/util"
	"github.com/coder/coder/codersdk"
	"github.com/coder/envbuilder/devcontainer"
	"github.com/containerd/containerd/platforms"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/fatih/color"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
	"github.com/tailscale/hujson"
	"golang.org/x/xerrors"
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
	MagicDir = ".envbuilder"
)

var (
	ErrNoFallbackImage = errors.New("no fallback image has been specified")

	// MagicFile is a file that is created in the workspace
	// when envbuilder has already been run. This is used
	// to skip building when a container is restarting.
	// e.g. docker stop -> docker start
	MagicFile = filepath.Join(MagicDir, "built")
)

type Options struct {
	// SetupScript is the script to run before the init script.
	// It runs as the root user regardless of the user specified
	// in the devcontainer.json file.

	// SetupScript is ran as the root user prior to the init script.
	// It is used to configure envbuilder dynamically during the runtime.
	// e.g. specifying whether to start `systemd` or `tiny init` for PID 1.
	SetupScript string `env:"SETUP_SCRIPT"`

	// InitScript is the script to run to initialize the workspace.
	InitScript string `env:"INIT_SCRIPT"`

	// InitCommand is the command to run to initialize the workspace.
	InitCommand string `env:"INIT_COMMAND"`

	// InitArgs are the arguments to pass to the init command.
	// They are split according to `/bin/sh` rules with
	// https://github.com/kballard/go-shellquote
	InitArgs string `env:"INIT_ARGS"`

	// CacheRepo is the name of the container registry
	// to push the cache image to. If this is empty, the cache
	// will not be pushed.
	CacheRepo string `env:"CACHE_REPO"`

	// BaseImageCacheDir is the path to a directory where the base
	// image can be found. This should be a read-only directory
	// solely mounted for the purpose of caching the base image.
	BaseImageCacheDir string `env:"BASE_IMAGECACHE_DIR"`

	// LayerCacheDir is the path to a directory where built layers
	// will be stored. This spawns an in-memory registry to serve
	// the layers from.
	//
	// It will override CacheRepo if both are specified.
	LayerCacheDir string `env:"LAYER_CACHE_DIR"`

	// DevcontainerJSONPath is a relative or absolute path to a
	// devcontainer.json file. This can be used in cases where
	// one wants to substitute an edited devcontainer.json file
	// for the one that exists in the repo.
	DevcontainerJSONPath string `env:"DEVCONTAINER_JSON_PATH"`

	// DockerfilePath is a relative path to the Dockerfile that
	// will be used to build the workspace. This is an alternative
	// to using a devcontainer that some might find simpler.
	DockerfilePath string `env:"DOCKERFILE_PATH"`

	// DockerConfigBase64 is a base64 encoded Docker config
	// file that will be used to pull images from private
	// container registries.
	DockerConfigBase64 string `env:"DOCKER_CONFIG_BASE64"`

	// FallbackImage is the image to use if no image is
	// specified in the devcontainer.json file and
	// a Dockerfile is not found.
	FallbackImage string `env:"FALLBACK_IMAGE"`

	// ForceSafe ignores any filesystem safety checks.
	// This could cause serious harm to your system!
	// This is used in cases where bypass is needed
	// to unblock customers!
	ForceSafe bool `env:"FORCE_SAFE"`

	// Insecure bypasses TLS verification when cloning
	// and pulling from container registries.
	Insecure bool `env:"INSECURE"`

	// IgnorePaths is a comma separated list of paths
	// to ignore when building the workspace.
	IgnorePaths []string `env:"IGNORE_PATHS"`

	// SkipRebuild skips building if the MagicFile exists.
	// This is used to skip building when a container is
	// restarting. e.g. docker stop -> docker start
	// This value can always be set to true - even if the
	// container is being started for the first time.
	SkipRebuild bool `env:"SKIP_REBUILD"`

	// GitURL is the URL of the Git repository to clone.
	// This is optional!
	GitURL string `env:"GIT_URL"`

	// GitCloneDepth is the depth to use when cloning
	// the Git repository.
	GitCloneDepth int `env:"GIT_CLONE_DEPTH"`

	// GitCloneSingleBranch clones only a single branch
	// of the Git repository.
	GitCloneSingleBranch bool `env:"GIT_CLONE_SINGLE_BRANCH"`

	// GitUsername is the username to use for Git authentication.
	// This is optional!
	GitUsername string `env:"GIT_USERNAME"`

	// GitPassword is the password to use for Git authentication.
	// This is optional!
	GitPassword string `env:"GIT_PASSWORD"`

	// WorkspaceFolder is the path to the workspace folder
	// that will be built. This is optional!
	WorkspaceFolder string `env:"WORKSPACE_FOLDER"`

	// SSLCertBase64 is the content of an SSL cert file.
	// This is useful for self-signed certificates.
	SSLCertBase64 string `env:"SSL_CERT_BASE64"`

	// Logger is the logger to use for all operations.
	Logger func(level codersdk.LogLevel, format string, args ...interface{})

	// Filesystem is the filesystem to use for all operations.
	// Defaults to the host filesystem.
	Filesystem billy.Filesystem
}

// DockerConfig represents the Docker configuration file.
type DockerConfig configfile.ConfigFile

// Run runs the envbuilder.
func Run(ctx context.Context, options Options) error {
	if options.InitScript == "" {
		options.InitScript = "sleep infinity"
	}
	if options.InitCommand == "" {
		options.InitCommand = "/bin/sh"
	}
	if options.IgnorePaths == nil {
		// Kubernetes frequently stores secrets in /var/run/secrets, and
		// other applications might as well. This seems to be a sensible
		// default, but if that changes, it's simple to adjust.
		options.IgnorePaths = []string{"/var/run"}
	}
	// Default to the shell!
	initArgs := []string{"-c", options.InitScript}
	if options.InitArgs != "" {
		var err error
		initArgs, err = shellquote.Split(options.InitArgs)
		if err != nil {
			return fmt.Errorf("parse init args: %w", err)
		}
	}
	if options.Filesystem == nil {
		options.Filesystem = &osfsWithChmod{osfs.New("/")}
	}
	if options.WorkspaceFolder == "" {
		var err error
		options.WorkspaceFolder, err = DefaultWorkspaceFolder(options.GitURL)
		if err != nil {
			return err
		}
	}
	logf := options.Logger
	stageNumber := 1
	startStage := func(format string, args ...interface{}) func(format string, args ...interface{}) {
		now := time.Now()
		stageNum := stageNumber
		stageNumber++
		logf(codersdk.LogLevelInfo, "#%d: %s", stageNum, fmt.Sprintf(format, args...))

		return func(format string, args ...interface{}) {
			logf(codersdk.LogLevelInfo, "#%d: %s [%s]", stageNum, fmt.Sprintf(format, args...), time.Since(now))
		}
	}

	logf(codersdk.LogLevelInfo, "%s - Build development environments from repositories in a container", newColor(color.Bold).Sprintf("envbuilder"))

	var caBundle []byte
	if options.SSLCertBase64 != "" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return xerrors.Errorf("get global system cert pool: %w", err)
		}
		data, err := base64.StdEncoding.DecodeString(options.SSLCertBase64)
		if err != nil {
			return xerrors.Errorf("base64 decode ssl cert: %w", err)
		}
		ok := certPool.AppendCertsFromPEM(data)
		if !ok {
			return xerrors.Errorf("failed to append the ssl cert to the global pool: %s", data)
		}
		caBundle = data
	}

	if options.DockerConfigBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(options.DockerConfigBase64)
		if err != nil {
			return fmt.Errorf("decode docker config: %w", err)
		}
		var configFile DockerConfig
		decoded, err = hujson.Standardize(decoded)
		if err != nil {
			return fmt.Errorf("humanize json for docker config: %w", err)
		}
		err = json.Unmarshal(decoded, &configFile)
		if err != nil {
			return fmt.Errorf("parse docker config: %w", err)
		}
		err = os.WriteFile(filepath.Join("/", MagicDir, "config.json"), decoded, 0644)
		if err != nil {
			return fmt.Errorf("write docker config: %w", err)
		}
	}

	var fallbackErr error
	var cloned bool
	if options.GitURL != "" {
		endStage := startStage("📦 Cloning %s to %s...",
			newColor(color.FgCyan).Sprintf(options.GitURL),
			newColor(color.FgCyan).Sprintf(options.WorkspaceFolder),
		)

		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		go func() {
			data := make([]byte, 4096)
			for {
				read, err := reader.Read(data)
				if err != nil {
					return
				}
				content := data[:read]
				for _, line := range strings.Split(string(content), "\r") {
					if line == "" {
						continue
					}
					logf(codersdk.LogLevelInfo, "#1: %s", strings.TrimSpace(line))
				}
			}
		}()

		if options.GitUsername != "" || options.GitPassword != "" {
			gitURL, err := url.Parse(options.GitURL)
			if err != nil {
				return fmt.Errorf("parse git url: %w", err)
			}
			gitURL.User = url.UserPassword(options.GitUsername, options.GitPassword)
			options.GitURL = gitURL.String()
		}

		cloned, fallbackErr = CloneRepo(ctx, CloneRepoOptions{
			Path:     options.WorkspaceFolder,
			Storage:  options.Filesystem,
			RepoURL:  options.GitURL,
			Insecure: options.Insecure,
			Progress: writer,
			RepoAuth: &githttp.BasicAuth{
				Username: options.GitUsername,
				Password: options.GitPassword,
			},
			SingleBranch: options.GitCloneSingleBranch,
			Depth:        options.GitCloneDepth,
			CABundle:     caBundle,
		})
		if fallbackErr == nil {
			if cloned {
				endStage("📦 Cloned repository!")
			} else {
				endStage("📦 The repository already exists!")
			}
		} else {
			logf(codersdk.LogLevelError, "Failed to clone repository: %s", fallbackErr.Error())
			logf(codersdk.LogLevelError, "Falling back to the default image...")
		}
	}

	defaultBuildParams := func() (*devcontainer.Compiled, error) {
		dockerfile := filepath.Join(MagicDir, "Dockerfile")
		file, err := options.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if options.FallbackImage == "" {
			if fallbackErr != nil {
				return nil, xerrors.Errorf("%s: %w", fallbackErr.Error(), ErrNoFallbackImage)
			}
			// We can't use errors.Join here because our tests
			// don't support parsing a multiline error.
			return nil, ErrNoFallbackImage
		}
		content := "FROM " + options.FallbackImage
		_, err = file.Write([]byte(content))
		if err != nil {
			return nil, err
		}
		return &devcontainer.Compiled{
			DockerfilePath:    dockerfile,
			DockerfileContent: content,
			BuildContext:      MagicDir,
		}, nil
	}

	var buildParams *devcontainer.Compiled
	if options.DockerfilePath == "" {
		// Only look for a devcontainer if a Dockerfile wasn't specified.
		// devcontainer is a standard, so it's reasonable to be the default.
		devcontainerDir := filepath.Join(options.WorkspaceFolder, ".devcontainer")
		devcontainerPath := options.DevcontainerJSONPath
		if devcontainerPath == "" {
			devcontainerPath = "devcontainer.json"
		}
		if !filepath.IsAbs(devcontainerPath) {
			devcontainerPath = filepath.Join(devcontainerDir, devcontainerPath)
		}
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
			devContainer, err := devcontainer.Parse(content)
			if err == nil {
				var fallbackDockerfile string
				if !devContainer.HasImage() && !devContainer.HasDockerfile() {
					defaultParams, err := defaultBuildParams()
					if err != nil {
						return fmt.Errorf("no Dockerfile or image found: %w", err)
					}
					logf(codersdk.LogLevelInfo, "No Dockerfile or image specified; falling back to the default image...")
					fallbackDockerfile = defaultParams.DockerfilePath
				}
				buildParams, err = devContainer.Compile(options.Filesystem, devcontainerDir, MagicDir, fallbackDockerfile)
				if err != nil {
					return fmt.Errorf("compile devcontainer.json: %w", err)
				}
			} else {
				logf(codersdk.LogLevelError, "Failed to parse devcontainer.json: %s", err.Error())
				logf(codersdk.LogLevelError, "Falling back to the default image...")
			}
		}
	} else {
		// If a Dockerfile was specified, we use that.
		dockerfilePath := filepath.Join(options.WorkspaceFolder, options.DockerfilePath)
		dockerfile, err := options.Filesystem.Open(dockerfilePath)
		if err == nil {
			content, err := io.ReadAll(dockerfile)
			if err != nil {
				return fmt.Errorf("read Dockerfile: %w", err)
			}
			buildParams = &devcontainer.Compiled{
				DockerfilePath:    dockerfilePath,
				DockerfileContent: string(content),
				BuildContext:      options.WorkspaceFolder,
			}
		}
	}

	if buildParams == nil {
		// If there isn't a devcontainer.json file in the repository,
		// we fallback to whatever the `DefaultImage` is.
		var err error
		buildParams, err = defaultBuildParams()
		if err != nil {
			return fmt.Errorf("no Dockerfile or devcontainer.json found: %w", err)
		}
	}

	HijackLogrus(func(entry *logrus.Entry) {
		for _, line := range strings.Split(entry.Message, "\r") {
			logf(codersdk.LogLevelInfo, "#2: %s", color.HiBlackString(line))
		}
	})

	var closeAfterBuild func()
	// Allows quick testing of layer caching using a local directory!
	if options.LayerCacheDir != "" {
		cfg := &configuration.Configuration{
			Storage: configuration.Storage{
				"filesystem": configuration.Parameters{
					"rootdirectory": options.LayerCacheDir,
				},
			},
		}

		// Disable all logging from the registry...
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		entry := logrus.NewEntry(logger)
		dcontext.SetDefaultLogger(entry)
		ctx = dcontext.WithLogger(ctx, entry)

		// Spawn an in-memory registry to cache built layers...
		registry := handlers.NewApp(ctx, cfg)

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		tcpAddr, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			return fmt.Errorf("listener addr was of wrong type: %T", listener.Addr())
		}
		srv := &http.Server{
			Handler: registry,
		}
		go func() {
			err := srv.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf(codersdk.LogLevelError, "Failed to serve registry: %s", err.Error())
			}
		}()
		closeAfterBuild = func() {
			_ = srv.Close()
			_ = listener.Close()
		}
		if options.CacheRepo != "" {
			logf(codersdk.LogLevelWarn, "Overriding cache repo with local registry...")
		}
		options.CacheRepo = fmt.Sprintf("localhost:%d/local/cache", tcpAddr.Port)
	}

	// IgnorePaths in the Kaniko options doesn't properly ignore paths.
	// So we add them to the default ignore list. See:
	// https://github.com/GoogleContainerTools/kaniko/blob/63be4990ca5a60bdf06ddc4d10aa4eca0c0bc714/cmd/executor/cmd/root.go#L136
	ignorePaths := append([]string{
		MagicDir,
		options.LayerCacheDir,
		options.WorkspaceFolder,
	}, options.IgnorePaths...)

	for _, ignorePath := range ignorePaths {
		util.AddToDefaultIgnoreList(util.IgnoreListEntry{
			Path:            ignorePath,
			PrefixMatchOnly: false,
		})
	}

	build := func() (v1.Image, error) {
		_, err := options.Filesystem.Stat(MagicFile)
		if err == nil && options.SkipRebuild {
			endStage := startStage("🏗️ Skipping build because of cache...")
			imageRef, err := devcontainer.ImageFromDockerfile(buildParams.DockerfileContent)
			if err != nil {
				return nil, fmt.Errorf("image from dockerfile: %w", err)
			}
			image, err := remote.Image(imageRef, remote.WithAuthFromKeychain(creds.GetKeychain()))
			if err != nil {
				return nil, fmt.Errorf("image from remote: %w", err)
			}
			endStage("🏗️ Found image from remote!")
			return image, nil
		}

		// This is required for deleting the filesystem prior to build!
		err = util.InitIgnoreList(true)
		if err != nil {
			return nil, fmt.Errorf("init ignore list: %w", err)
		}

		// It's possible that the container will already have files in it, and
		// we don't want to merge a new container with the old one.
		err = util.DeleteFilesystem()
		if err != nil {
			return nil, fmt.Errorf("delete filesystem: %w", err)
		}

		stdoutReader, stdoutWriter := io.Pipe()
		stderrReader, stderrWriter := io.Pipe()
		defer stdoutReader.Close()
		defer stdoutWriter.Close()
		defer stderrReader.Close()
		defer stderrWriter.Close()
		go func() {
			scanner := bufio.NewScanner(stdoutReader)
			for scanner.Scan() {
				logf(codersdk.LogLevelInfo, "%s", scanner.Text())
			}
		}()
		go func() {
			scanner := bufio.NewScanner(stderrReader)
			for scanner.Scan() {
				logf(codersdk.LogLevelInfo, "%s", scanner.Text())
			}
		}()

		endStage := startStage("🏗️ Building image...")
		// At this point we have all the context, we can now build!
		image, err := executor.DoBuild(&config.KanikoOptions{
			// Boilerplate!
			CustomPlatform:    platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
			SnapshotMode:      "redo",
			RunV2:             true,
			RunStdout:         stdoutWriter,
			RunStderr:         stderrWriter,
			Destinations:      []string{"local"},
			CacheRunLayers:    true,
			CacheCopyLayers:   true,
			CompressedCaching: true,
			Compression:       config.ZStd,
			// Maps to "default" level, ~100-300 MB/sec according to
			// benchmarks in klauspost/compress README
			// https://github.com/klauspost/compress/blob/67a538e2b4df11f8ec7139388838a13bce84b5d5/zstd/encoder_options.go#L188
			CompressionLevel: 3,
			CacheOptions: config.CacheOptions{
				// Cache for a week by default!
				CacheTTL: time.Hour * 24 * 7,
				CacheDir: options.BaseImageCacheDir,
			},
			ForceUnpack:       true,
			BuildArgs:         buildParams.BuildArgs,
			CacheRepo:         options.CacheRepo,
			Cache:             options.CacheRepo != "",
			DockerfilePath:    buildParams.DockerfilePath,
			DockerfileContent: buildParams.DockerfileContent,
			RegistryOptions: config.RegistryOptions{
				Insecure:      options.Insecure,
				InsecurePull:  options.Insecure,
				SkipTLSVerify: options.Insecure,
			},
			SrcContext: buildParams.BuildContext,
		})
		if err != nil {
			return nil, err
		}
		endStage("🏗️ Built image!")
		return image, err
	}

	// At this point we have all the context, we can now build!
	image, err := build()
	if err != nil {
		fallback := false
		switch {
		case strings.Contains(err.Error(), "parsing dockerfile"):
			fallback = true
			fallbackErr = err
		case strings.Contains(err.Error(), "error building stage"):
			fallback = true
			fallbackErr = err
		// This occurs when the image cannot be found!
		case strings.Contains(err.Error(), "authentication required"):
			fallback = true
			fallbackErr = err
		// This occurs from Docker Hub when the image cannot be found!
		case strings.Contains(err.Error(), "manifest unknown"):
			fallback = true
			fallbackErr = err
		case strings.Contains(err.Error(), "unexpected status code 401 Unauthorized"):
			logf(codersdk.LogLevelError, "Unable to pull the provided image. Ensure your registry credentials are correct!")
		}
		if !fallback {
			return err
		}
		logf(codersdk.LogLevelError, "Failed to build: %s", err)
		logf(codersdk.LogLevelError, "Falling back to the default image...")
		buildParams, err = defaultBuildParams()
		if err != nil {
			return err
		}
		image, err = build()
	}
	if err != nil {
		return fmt.Errorf("build with kaniko: %w", err)
	}

	if closeAfterBuild != nil {
		closeAfterBuild()
	}

	// Create the magic file to indicate that this build
	// has already been ran before!
	file, err := options.Filesystem.Create(MagicFile)
	if err != nil {
		return fmt.Errorf("create magic file: %w", err)
	}
	_ = file.Close()

	configFile, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("get image config: %w", err)
	}

	// devcontainer metadata can be persisted through a standard label
	devContainerMetadata, exists := configFile.Config.Labels["devcontainer.metadata"]
	if exists {
		var devContainer []*devcontainer.Spec
		devContainerMetadataBytes, err := hujson.Standardize([]byte(devContainerMetadata))
		if err != nil {
			return fmt.Errorf("humanize json for dev container metadata: %w", err)
		}
		err = json.Unmarshal(devContainerMetadataBytes, &devContainer)
		if err != nil {
			return fmt.Errorf("unmarshal metadata: %w", err)
		}
		logf(codersdk.LogLevelInfo, "#3: 👀 Found devcontainer.json label metadata in image...")
		for _, container := range devContainer {
			if container.RemoteUser != "" {
				logf(codersdk.LogLevelInfo, "#3: 🧑 Updating the user to %q!", container.RemoteUser)

				configFile.Config.User = container.RemoteUser
			}
			if container.RemoteEnv != nil {
				for key, value := range container.RemoteEnv {
					os.Setenv(key, value)
				}
			}
		}
	}

	// Sanitize the environment of any options!
	unsetOptionsEnv()

	// Remove the Docker config secret file!
	err = os.Remove(filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove docker config: %w", err)
	}

	environ, err := os.ReadFile("/etc/environment")
	if err == nil {
		for _, env := range strings.Split(string(environ), "\n") {
			pair := strings.SplitN(env, "=", 2)
			if len(pair) != 2 {
				continue
			}
			os.Setenv(pair[0], pair[1])
		}
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

	username := configFile.Config.User
	if buildParams.User != "" {
		username = buildParams.User
	}
	if username == "" {
		logf(codersdk.LogLevelWarn, "#3: no user specified, using root")
	}
	var user *user.User
	var uid int
	var gid int
	updateUser := func(username string) error {
		var err error
		user, err = findUser(username)
		if err != nil {
			return fmt.Errorf("find user: %w", err)
		}
		uid, err = strconv.Atoi(user.Uid)
		if err != nil {
			return fmt.Errorf("parse uid: %w", err)
		}
		gid, err = strconv.Atoi(user.Gid)
		if err != nil {
			return fmt.Errorf("parse gid: %w", err)
		}
		if user.Username == "" && uid == 0 {
			// This is nice for the visual display in log messages,
			// but has no actual functionality since the credential
			// in the syscall is what matters.
			user.Username = "root"
			user.HomeDir = "/root"
		}
		return err
	}
	err = updateUser(username)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}

	// We only need to do this if we cloned!
	// Git doesn't store file permissions as part of the repository.
	if cloned {
		endStage := startStage("🔄 Updating the ownership of the workspace...")
		// By default, we clone the Git repository into the workspace folder.
		// It will have root permissions, because that's the user that built it.
		//
		// We need to change the ownership of the files to the user that will
		// be running the init script.
		filepath.Walk(options.WorkspaceFolder, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, uid, gid)
		})
		endStage("👤 Updated the ownership of the workspace!")
	}

	err = os.MkdirAll(options.WorkspaceFolder, 0755)
	if err != nil {
		return fmt.Errorf("create workspace folder: %w", err)
	}
	err = os.Chdir(options.WorkspaceFolder)
	if err != nil {
		return fmt.Errorf("change directory: %w", err)
	}

	// The setup script can specify a custom initialization command
	// and arguments to run instead of the default shell.
	//
	// This is useful for hooking into the environment for a specific
	// init to PID 1.
	if options.SetupScript != "" {
		// We execute the initialize script as the root user!
		os.Setenv("HOME", "/root")

		logf(codersdk.LogLevelInfo, "=== Running the setup command %q as the root user...", options.SetupScript)

		envKey := "ENVBUILDER_ENV"
		envFile := filepath.Join("/", MagicDir, "environ")
		file, err := os.Create(envFile)
		if err != nil {
			return fmt.Errorf("create environ file: %w", err)
		}
		_ = file.Close()

		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", options.SetupScript)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("%s=%s", envKey, envFile),
			fmt.Sprintf("TARGET_USER=%s", user.Username),
		)
		cmd.Dir = options.WorkspaceFolder
		// This allows for a really nice and clean experience to experiement with!
		// e.g. docker run --it --rm -e INIT_SCRIPT bash ...
		if isatty.IsTerminal(os.Stdout.Fd()) && isatty.IsTerminal(os.Stdin.Fd()) {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
		} else {
			var buf bytes.Buffer
			go func() {
				scanner := bufio.NewScanner(&buf)
				for scanner.Scan() {
					logf(codersdk.LogLevelInfo, "%s", scanner.Text())
				}
			}()

			cmd.Stdout = &buf
			cmd.Stderr = &buf
		}
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("run setup script: %w", err)
		}

		environ, err := os.ReadFile(envFile)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
			environ = []byte{}
		}
		if err != nil {
			return fmt.Errorf("read environ: %w", err)
		}
		updatedCommand := false
		updatedArgs := false
		for _, env := range strings.Split(string(environ), "\n") {
			pair := strings.SplitN(env, "=", 2)
			if len(pair) != 2 {
				continue
			}
			key := pair[0]
			switch key {
			case "INIT_COMMAND":
				options.InitCommand = pair[1]
				updatedCommand = true
			case "INIT_ARGS":
				initArgs, err = shellquote.Split(pair[1])
				if err != nil {
					return fmt.Errorf("split init args: %w", err)
				}
				updatedArgs = true
			case "TARGET_USER":
				err = updateUser(pair[1])
				if err != nil {
					return fmt.Errorf("update user: %w", err)
				}
			default:
				return fmt.Errorf("unknown environ key %q", key)
			}
		}
		if updatedCommand && !updatedArgs {
			// Because our default is a shell we need to empty the args
			// if the command was updated. This a tragic hack, but it works.
			initArgs = []string{}
		}
	}

	// Hop into the user that should execute the initialize script!
	os.Setenv("HOME", user.HomeDir)

	err = syscall.Setgid(gid)
	if err != nil {
		return fmt.Errorf("set gid: %w", err)
	}
	err = syscall.Setuid(uid)
	if err != nil {
		return fmt.Errorf("set uid: %w", err)
	}

	logf(codersdk.LogLevelInfo, "=== Running the init command %s %+v as the %q user...", options.InitCommand, initArgs, user.Username)

	err = syscall.Exec(options.InitCommand, append([]string{options.InitCommand}, initArgs...), os.Environ())
	if err != nil {
		return fmt.Errorf("exec init script: %w", err)
	}
	return nil
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

// OptionsFromEnv returns a set of options from environment variables.
func OptionsFromEnv(getEnv func(string) (string, bool)) Options {
	options := Options{}

	val := reflect.ValueOf(&options).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldTyp := typ.Field(i)
		env := fieldTyp.Tag.Get("env")
		if env == "" {
			continue
		}
		switch fieldTyp.Type.Kind() {
		case reflect.String:
			v, _ := getEnv(env)
			field.SetString(v)
		case reflect.Bool:
			e, _ := getEnv(env)
			v, _ := strconv.ParseBool(e)
			field.SetBool(v)
		case reflect.Slice:
			v, ok := getEnv(env)
			if !ok {
				continue
			}
			field.Set(reflect.ValueOf(strings.Split(v, ",")))
		}
	}

	return options
}

// unsetOptionsEnv unsets all environment variables that are used
// to configure the options.
func unsetOptionsEnv() {
	val := reflect.ValueOf(&Options{}).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		fieldTyp := typ.Field(i)
		env := fieldTyp.Tag.Get("env")
		if env == "" {
			continue
		}
		os.Unsetenv(env)
	}
}

func newColor(value ...color.Attribute) *color.Color {
	c := color.New(value...)
	c.EnableColor()
	return c
}

type osfsWithChmod struct {
	billy.Filesystem
}

func (fs *osfsWithChmod) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}
