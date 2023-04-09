package envbuilder

import (
	"bufio"
	"bytes"
	"context"
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
	"github.com/containerd/containerd/platforms"
	"github.com/fatih/color"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
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
	MagicDir = "envbuilder"
)

type Options struct {
	// InitScript is the script to run to initialize the workspace.
	InitScript string `env:"INIT_SCRIPT"`

	// CacheRepo is the name of the container registry
	// to push the cache image to. If this is empty, the cache
	// will not be pushed.
	CacheRepo string `env:"CACHE_REPO"`

	// DockerfilePath is a relative path to the workspace
	// folder that will be used to build the workspace.
	// This is an alternative to using a devcontainer
	// that some might find simpler.
	DockerfilePath string `env:"DOCKERFILE_PATH"`

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

	// GitUsername is the username to use for Git authentication.
	// This is optional!
	GitUsername string `env:"GIT_USERNAME"`

	// GitPassword is the password to use for Git authentication.
	// This is optional!
	GitPassword string `env:"GIT_PASSWORD"`

	// WorkspaceFolder is the path to the workspace folder
	// that will be built. This is optional!
	WorkspaceFolder string `env:"WORKSPACE_FOLDER"`

	// Logger is the logger to use for all operations.
	Logger func(format string, args ...interface{})

	// Filesystem is the filesystem to use for all operations.
	// Defaults to the host filesystem.
	Filesystem billy.Filesystem
}

// Run runs the envbuilder.
func Run(ctx context.Context, options Options) error {
	if options.InitScript == "" {
		options.InitScript = "sleep infinity"
	}
	if options.Filesystem == nil {
		options.Filesystem = osfs.New("/")
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
		logf("#%d: %s", stageNum, fmt.Sprintf(format, args...))

		return func(format string, args ...interface{}) {
			logf("#%d: %s [%dms]", stageNum, fmt.Sprintf(format, args...), time.Since(now).Milliseconds())
		}
	}

	logf("%s - Build development environments from repositories in a container", color.New(color.Bold).Sprintf("envbuilder"))

	if options.GitURL != "" {
		endStage := startStage("Cloning Repository %s to %s...", options.GitURL, options.WorkspaceFolder)

		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		go func() {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				logf("git: %s", scanner.Text())
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

		err := CloneRepo(ctx, CloneRepoOptions{
			Path:     options.WorkspaceFolder,
			Storage:  options.Filesystem,
			RepoURL:  options.GitURL,
			Insecure: options.Insecure,
			Progress: writer,
		})
		if err != nil {
			return err
		}

		endStage("Cloned Repository")
	}

	var buildParams *BuildParameters

	defaultBuildParams := func() error {
		dockerfile := filepath.Join(MagicDir, "Dockerfile")
		file, err := options.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		if options.FallbackImage == "" {
			return ErrNoFallbackImage
		}
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
			return fmt.Errorf("no Dockerfile or devcontainer.json found: %w", err)
		}
	}

	HijackLogrus(func(entry *logrus.Entry) {
		logf("#2: %s", entry.Message)
	})

	build := func() (v1.Image, error) {
		// At this point we have all the context, we can now build!
		return executor.DoBuild(&config.KanikoOptions{
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
			ForceUnpack:    true,
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
	}

	// At this point we have all the context, we can now build!
	image, err := build()
	if err != nil {
		fallback := false
		switch {
		case strings.Contains(err.Error(), "parsing dockerfile"):
			fallback = true
		}
		if !fallback {
			return err
		}
		logf("Failed to build with the provided context: %s", err)
		logf("Falling back to the default image...")
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

	username := configFile.Config.User
	if buildParams.User != "" {
		username = buildParams.User
	}
	if username == "" {
		logf("#3: no user specified, using root")
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

	logf("=== Running the init command %q as the %q user...", options.InitScript, user.Username)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", options.InitScript)
	cmd.Env = os.Environ()
	cmd.Dir = options.WorkspaceFolder
	cmd.SysProcAttr = sysProcAttr

	var buf bytes.Buffer
	go func() {
		scanner := bufio.NewScanner(&buf)
		for scanner.Scan() {
			logf("%s", scanner.Text())
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

func printOptions(logf func(format string, args ...interface{}), options Options) {
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
			logf("option %s: %q", fieldTyp.Name, field.String())
		case reflect.Bool:
			field.Bool()
		}
	}
}

func stage() {

}
