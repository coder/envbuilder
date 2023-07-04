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

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/executor"
	"github.com/coder/coder/codersdk"
	"github.com/coder/envbuilder/devcontainer"
	"github.com/containerd/containerd/platforms"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/fatih/color"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

var (
	ErrNoFallbackImage = errors.New("no fallback image has been specified")
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

type Options struct {
	// InitScript is the script to run to initialize the workspace.
	InitScript string `env:"INIT_SCRIPT"`

	// CacheRepo is the name of the container registry
	// to push the cache image to. If this is empty, the cache
	// will not be pushed.
	CacheRepo string `env:"CACHE_REPO"`

	// CacheDir is the path to the directory where the cache
	// will be stored. If this is empty, the cache will not
	// be used.
	CacheDir string `env:"CACHE_DIR"`

	// DockerfilePath is a relative path to the workspace
	// folder that will be used to build the workspace.
	// This is an alternative to using a devcontainer
	// that some might find simpler.
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

	var buildParams *devcontainer.Compiled

	defaultBuildParams := func() error {
		dockerfile := filepath.Join(MagicDir, "Dockerfile")
		file, err := options.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		if options.FallbackImage == "" {
			if fallbackErr != nil {
				return xerrors.Errorf("%s: %w", fallbackErr.Error(), ErrNoFallbackImage)
			}
			// We can't use errors.Join here because our tests
			// don't support parsing a multiline error.
			return ErrNoFallbackImage
		}
		_, err = file.Write([]byte("FROM " + options.FallbackImage))
		if err != nil {
			return err
		}
		buildParams = &devcontainer.Compiled{
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
			devContainer, err := devcontainer.Parse(content)
			if err == nil {
				buildParams, err = devContainer.Compile(options.Filesystem, devcontainerDir, MagicDir)
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
		_, err := options.Filesystem.Stat(dockerfilePath)
		if err == nil {
			buildParams = &devcontainer.Compiled{
				DockerfilePath: dockerfilePath,
				BuildContext:   options.WorkspaceFolder,
			}
		}
	}

	if buildParams == nil {
		// If there isn't a devcontainer.json file in the repository,
		// we fallback to whatever the `DefaultImage` is.
		err := defaultBuildParams()
		if err != nil {
			return fmt.Errorf("no Dockerfile or devcontainer.json found: %w", err)
		}
	}

	HijackLogrus(func(entry *logrus.Entry) {
		for _, line := range strings.Split(entry.Message, "\r") {
			logf(codersdk.LogLevelInfo, "#2: %s", color.HiBlackString(line))
		}
	})

	build := func() (v1.Image, error) {
		endStage := startStage("🏗️ Building image...")
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
				CacheDir: options.CacheDir,
			},
			ForceUnpack:       true,
			BuildArgs:         buildParams.BuildArgs,
			CacheRepo:         options.CacheRepo,
			Cache:             true,
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
		case strings.Contains(err.Error(), "unexpected status code 401 Unauthorized"):
			logf(codersdk.LogLevelError, "Unable to pull the provided image. Ensure your registry credentials are correct!")
		}
		if !fallback {
			return err
		}
		logf(codersdk.LogLevelError, "Failed to build: %s", err)
		logf(codersdk.LogLevelError, "Falling back to the default image...")
		err = defaultBuildParams()
		if err != nil {
			return err
		}
		image, err = build()
	}
	if err != nil {
		return fmt.Errorf("build with kaniko: %w", err)
	}

	configFile, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("get image config: %w", err)
	}

	// devcontainer metadata can be persisted through a standard label
	devContainerMetadata, exists := configFile.Config.Labels["devcontainer.metadata"]
	if exists {
		var devContainer []*devcontainer.Spec
		err := json.Unmarshal([]byte(devContainerMetadata), &devContainer)
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

	username := configFile.Config.User
	if buildParams.User != "" {
		username = buildParams.User
	}
	if username == "" {
		logf(codersdk.LogLevelWarn, "#3: no user specified, using root")
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
	if user.Username == "" && uid == 0 {
		// This is nice for the visual display in log messages,
		// but has no actual functionality since the credential
		// in the syscall is what matters.
		user.Username = "root"
		user.HomeDir = "/root"
	}
	os.Setenv("HOME", user.HomeDir)

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

	sysProcAttr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}

	unsetOptionsEnv()

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

	// Remove the Docker config secret file!
	err = os.Remove(filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove docker config: %w", err)
	}

	err = os.MkdirAll(options.WorkspaceFolder, 0755)
	if err != nil {
		return fmt.Errorf("create workspace folder: %w", err)
	}

	logf(codersdk.LogLevelInfo, "=== Running the init command %q as the %q user...", options.InitScript, user.Username)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", options.InitScript)
	cmd.Env = os.Environ()
	cmd.Dir = options.WorkspaceFolder
	cmd.SysProcAttr = sysProcAttr

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
		return fmt.Errorf("run init script: %w", err)
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
func OptionsFromEnv(getEnv func(string) string) Options {
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
			field.SetString(getEnv(env))
		case reflect.Bool:
			v, _ := strconv.ParseBool(getEnv(env))
			field.SetBool(v)
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

func printOptions(logf func(level codersdk.LogLevel, format string, args ...interface{}), options Options) {
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
			logf(codersdk.LogLevelDebug, "option %s: %q", fieldTyp.Name, field.String())
		case reflect.Bool:
			field.Bool()
		}
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
