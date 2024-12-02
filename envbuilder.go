package envbuilder

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/envbuilder/buildinfo"
	"github.com/coder/envbuilder/git"
	"github.com/coder/envbuilder/options"
	"github.com/go-git/go-billy/v5"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/creds"
	"github.com/GoogleContainerTools/kaniko/pkg/executor"
	"github.com/GoogleContainerTools/kaniko/pkg/util"
	"github.com/coder/envbuilder/devcontainer"
	"github.com/coder/envbuilder/internal/ebutil"
	"github.com/coder/envbuilder/internal/workingdir"
	"github.com/coder/envbuilder/log"
	"github.com/containerd/platforms"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/fatih/color"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kballard/go-shellquote"
	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"
	"github.com/tailscale/hujson"
	"golang.org/x/xerrors"
)

// ErrNoFallbackImage is returned when no fallback image has been specified.
var ErrNoFallbackImage = errors.New("no fallback image has been specified")

// DockerConfig represents the Docker configuration file.
type DockerConfig = configfile.ConfigFile

type runtimeDataStore struct {
	// Runtime data.
	Image            bool                          `json:"-"`
	Built            bool                          `json:"-"`
	SkippedRebuild   bool                          `json:"-"`
	Scripts          devcontainer.LifecycleScripts `json:"-"`
	ImageEnv         []string                      `json:"-"`
	ContainerEnv     map[string]string             `json:"-"`
	RemoteEnv        map[string]string             `json:"-"`
	DevcontainerPath string                        `json:"-"`

	// Data stored in the magic image file.
	ContainerUser string `json:"container_user"`
}

type execArgsInfo struct {
	InitCommand string
	InitArgs    []string
	UserInfo    userInfo
	Environ     []string
}

// Run runs the envbuilder.
// Logger is the logf to use for all operations.
// Filesystem is the filesystem to use for all operations.
// Defaults to the host filesystem.
// preExec are any functions that should be called before exec'ing the init
// command. This is useful for ensuring that defers get run.
func Run(ctx context.Context, opts options.Options, preExec ...func()) error {
	var args execArgsInfo
	// Run in a separate function to ensure all defers run before we
	// setuid or exec.
	err := run(ctx, opts, &args)
	if err != nil {
		return err
	}

	err = syscall.Setgid(args.UserInfo.gid)
	if err != nil {
		return fmt.Errorf("set gid: %w", err)
	}
	err = syscall.Setuid(args.UserInfo.uid)
	if err != nil {
		return fmt.Errorf("set uid: %w", err)
	}

	opts.Logger(log.LevelInfo, "=== Running init command as user %q: %q", args.UserInfo.user.Username, append([]string{opts.InitCommand}, args.InitArgs...))
	for _, fn := range preExec {
		fn()
	}

	err = syscall.Exec(args.InitCommand, append([]string{args.InitCommand}, args.InitArgs...), args.Environ)
	if err != nil {
		return fmt.Errorf("exec init script: %w", err)
	}

	return errors.New("exec failed")
}

func run(ctx context.Context, opts options.Options, execArgs *execArgsInfo) error {
	defer options.UnsetEnv()

	workingDir := workingdir.At(opts.MagicDirBase)

	stageNumber := 0
	startStage := func(format string, args ...any) func(format string, args ...any) {
		now := time.Now()
		stageNumber++
		stageNum := stageNumber
		opts.Logger(log.LevelInfo, "#%d: %s", stageNum, fmt.Sprintf(format, args...))

		return func(format string, args ...any) {
			opts.Logger(log.LevelInfo, "#%d: %s [%s]", stageNum, fmt.Sprintf(format, args...), time.Since(now))
		}
	}

	if opts.GetCachedImage {
		return fmt.Errorf("developer error: use RunCacheProbe instead")
	}
	if opts.CacheRepo == "" && opts.PushImage {
		return fmt.Errorf("--cache-repo must be set when using --push-image")
	}

	// Default to the shell.
	execArgs.InitCommand = opts.InitCommand
	execArgs.InitArgs = []string{"-c", opts.InitScript}
	if opts.InitArgs != "" {
		var err error
		execArgs.InitArgs, err = shellquote.Split(opts.InitArgs)
		if err != nil {
			return fmt.Errorf("parse init args: %w", err)
		}
	}

	opts.Logger(log.LevelInfo, "%s %s - Build development environments from repositories in a container", newColor(color.Bold).Sprintf("envbuilder"), buildinfo.Version())

	cleanupDockerConfigOverride, err := initDockerConfigOverride(opts.Filesystem, opts.Logger, workingDir, opts.DockerConfigBase64)
	if err != nil {
		return err
	}
	defer func() {
		if err := cleanupDockerConfigOverride(); err != nil {
			opts.Logger(log.LevelError, "failed to cleanup docker config override: %w", err)
		}
	}() // best effort

	runtimeData := runtimeDataStore{
		ContainerEnv: make(map[string]string),
		RemoteEnv:    make(map[string]string),
	}
	if fileExists(opts.Filesystem, workingDir.Image()) {
		if err = parseMagicImageFile(opts.Filesystem, workingDir.Image(), &runtimeData); err != nil {
			return fmt.Errorf("parse magic image file: %w", err)
		}
		runtimeData.Image = true

		// Some options are only applicable for builds.
		if opts.RemoteRepoBuildMode {
			opts.Logger(log.LevelDebug, "Ignoring %s option, it is not supported when using a pre-built image.", options.WithEnvPrefix("REMOTE_REPO_BUILD_MODE"))
			opts.RemoteRepoBuildMode = false
		}
		if opts.ExportEnvFile != "" {
			// Currently we can't support this as we don't have access to the
			// post-build computed env vars to know which ones to export.
			opts.Logger(log.LevelWarn, "Ignoring %s option, it is not supported when using a pre-built image.", options.WithEnvPrefix("EXPORT_ENV_FILE"))
			opts.ExportEnvFile = ""
		}
	}
	runtimeData.Built = fileExists(opts.Filesystem, workingDir.Built())

	buildTimeWorkspaceFolder := opts.WorkspaceFolder
	var fallbackErr error
	var cloned bool
	if opts.GitURL != "" {
		endStage := startStage("📦 Cloning %s to %s...",
			newColor(color.FgCyan).Sprintf(opts.GitURL),
			newColor(color.FgCyan).Sprintf(opts.WorkspaceFolder),
		)
		stageNum := stageNumber
		logStage := func(format string, args ...any) {
			opts.Logger(log.LevelInfo, "#%d: %s", stageNum, fmt.Sprintf(format, args...))
		}

		cloneOpts, err := git.CloneOptionsFromOptions(logStage, opts)
		if err != nil {
			return fmt.Errorf("git clone options: %w", err)
		}

		w := git.ProgressWriter(logStage)
		defer w.Close()
		cloneOpts.Progress = w

		cloned, fallbackErr = git.CloneRepo(ctx, logStage, cloneOpts)
		if fallbackErr == nil {
			if cloned {
				endStage("📦 Cloned repository!")
			} else {
				endStage("📦 The repository already exists!")
			}
		} else {
			opts.Logger(log.LevelError, "Failed to clone repository: %s", fallbackErr.Error())
			if !runtimeData.Image {
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}
		}

		_ = w.Close()

		// Always clone the repo in remote repo build mode into a location that
		// we control that isn't affected by the users changes.
		if opts.RemoteRepoBuildMode {
			cloneOpts, err := git.CloneOptionsFromOptions(logStage, opts)
			if err != nil {
				return fmt.Errorf("git clone options: %w", err)
			}
			cloneOpts.Path = workingDir.Join("repo")

			endStage := startStage("📦 Remote repo build mode enabled, cloning %s to %s for build context...",
				newColor(color.FgCyan).Sprintf(opts.GitURL),
				newColor(color.FgCyan).Sprintf(cloneOpts.Path),
			)

			w := git.ProgressWriter(logStage)
			defer w.Close()
			cloneOpts.Progress = w

			fallbackErr = git.ShallowCloneRepo(ctx, logStage, cloneOpts)
			if fallbackErr == nil {
				endStage("📦 Cloned repository!")
				buildTimeWorkspaceFolder = cloneOpts.Path
			} else {
				opts.Logger(log.LevelError, "Failed to clone repository for remote repo mode: %s", fallbackErr.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}

			_ = w.Close()
		}
	}

	if !runtimeData.Image {
		defaultBuildParams := func() (*devcontainer.Compiled, error) {
			dockerfile := workingDir.Join("Dockerfile")
			file, err := opts.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return nil, err
			}
			defer file.Close()
			if opts.FallbackImage == "" {
				if fallbackErr != nil {
					return nil, xerrors.Errorf("%s: %w", fallbackErr.Error(), ErrNoFallbackImage)
				}
				// We can't use errors.Join here because our tests
				// don't support parsing a multiline error.
				return nil, ErrNoFallbackImage
			}
			content := "FROM " + opts.FallbackImage
			_, err = file.Write([]byte(content))
			if err != nil {
				return nil, err
			}
			return &devcontainer.Compiled{
				DockerfilePath:    dockerfile,
				DockerfileContent: content,
				BuildContext:      workingDir.Path(),
			}, nil
		}

		var buildParams *devcontainer.Compiled
		if opts.DockerfilePath == "" {
			// Only look for a devcontainer if a Dockerfile wasn't specified.
			// devcontainer is a standard, so it's reasonable to be the default.
			var devcontainerDir string
			var err error
			runtimeData.DevcontainerPath, devcontainerDir, err = findDevcontainerJSON(buildTimeWorkspaceFolder, opts)
			if err != nil {
				opts.Logger(log.LevelError, "Failed to locate devcontainer.json: %s", err.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			} else {
				// We know a devcontainer exists.
				// Let's parse it and use it!
				file, err := opts.Filesystem.Open(runtimeData.DevcontainerPath)
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
						opts.Logger(log.LevelInfo, "No Dockerfile or image specified; falling back to the default image...")
						fallbackDockerfile = defaultParams.DockerfilePath
					}
					buildParams, err = devContainer.Compile(opts.Filesystem, devcontainerDir, workingDir.Path(), fallbackDockerfile, opts.WorkspaceFolder, false, os.LookupEnv)
					if err != nil {
						return fmt.Errorf("compile devcontainer.json: %w", err)
					}
					if buildParams.User != "" {
						runtimeData.ContainerUser = buildParams.User
					}
					runtimeData.Scripts = devContainer.LifecycleScripts
				} else {
					opts.Logger(log.LevelError, "Failed to parse devcontainer.json: %s", err.Error())
					opts.Logger(log.LevelError, "Falling back to the default image...")
				}
			}
		} else {
			// If a Dockerfile was specified, we use that.
			dockerfilePath := filepath.Join(buildTimeWorkspaceFolder, opts.DockerfilePath)

			// If the dockerfilePath is specified and deeper than the base of WorkspaceFolder AND the BuildContextPath is
			// not defined, show a warning
			dockerfileDir := filepath.Dir(dockerfilePath)
			if dockerfileDir != filepath.Clean(buildTimeWorkspaceFolder) && opts.BuildContextPath == "" {
				opts.Logger(log.LevelWarn, "given dockerfile %q is below %q and no custom build context has been defined", dockerfilePath, buildTimeWorkspaceFolder)
				opts.Logger(log.LevelWarn, "\t-> set BUILD_CONTEXT_PATH to %q to fix", dockerfileDir)
			}

			dockerfile, err := opts.Filesystem.Open(dockerfilePath)
			if err == nil {
				content, err := io.ReadAll(dockerfile)
				if err != nil {
					return fmt.Errorf("read Dockerfile: %w", err)
				}
				buildParams = &devcontainer.Compiled{
					DockerfilePath:    dockerfilePath,
					DockerfileContent: string(content),
					BuildContext:      filepath.Join(buildTimeWorkspaceFolder, opts.BuildContextPath),
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

		lvl := log.LevelInfo
		if opts.Verbose {
			lvl = log.LevelDebug
		}
		log.HijackLogrus(lvl, func(entry *logrus.Entry) {
			for _, line := range strings.Split(entry.Message, "\r") {
				opts.Logger(log.FromLogrus(entry.Level), "#%d: %s", stageNumber, color.HiBlackString(line))
			}
		})

		if opts.LayerCacheDir != "" {
			if opts.CacheRepo != "" {
				opts.Logger(log.LevelWarn, "Overriding cache repo with local registry...")
			}
			localRegistry, closeLocalRegistry, err := serveLocalRegistry(ctx, opts.Logger, opts.LayerCacheDir)
			if err != nil {
				return err
			}
			defer closeLocalRegistry()
			opts.CacheRepo = localRegistry
		}

		// IgnorePaths in the Kaniko opts doesn't properly ignore paths.
		// So we add them to the default ignore list. See:
		// https://github.com/GoogleContainerTools/kaniko/blob/63be4990ca5a60bdf06ddc4d10aa4eca0c0bc714/cmd/executor/cmd/root.go#L136
		ignorePaths := append([]string{
			workingDir.Path(),
			opts.WorkspaceFolder,
			// See: https://github.com/coder/envbuilder/issues/37
			"/etc/resolv.conf",
		}, opts.IgnorePaths...)

		if opts.LayerCacheDir != "" {
			ignorePaths = append(ignorePaths, opts.LayerCacheDir)
		}

		for _, ignorePath := range ignorePaths {
			util.AddToDefaultIgnoreList(util.IgnoreListEntry{
				Path:            ignorePath,
				PrefixMatchOnly: false,
				AllowedPaths:    nil,
			})
		}

		// In order to allow 'resuming' envbuilder, embed the binary into the image
		// if it is being pushed.
		// As these files will be owned by root, it is considerate to clean up
		// after we're done!
		cleanupBuildContext := func() {}
		if opts.PushImage {
			// Add exceptions in Kaniko's ignorelist for these magic files we add.
			if err := util.AddAllowedPathToDefaultIgnoreList(opts.BinaryPath); err != nil {
				return fmt.Errorf("add envbuilder binary to ignore list: %w", err)
			}
			if err := util.AddAllowedPathToDefaultIgnoreList(workingDir.Image()); err != nil {
				return fmt.Errorf("add magic image file to ignore list: %w", err)
			}
			if err := util.AddAllowedPathToDefaultIgnoreList(workingDir.Features()); err != nil {
				return fmt.Errorf("add features to ignore list: %w", err)
			}
			magicTempDir := workingdir.At(buildParams.BuildContext, workingdir.TempDir)
			if err := opts.Filesystem.MkdirAll(magicTempDir.Path(), 0o755); err != nil {
				return fmt.Errorf("create magic temp dir in build context: %w", err)
			}
			// Add the magic directives that embed the binary into the built image.
			buildParams.DockerfileContent += workingdir.Directives

			envbuilderBinDest := filepath.Join(magicTempDir.Path(), "envbuilder")
			magicImageDest := magicTempDir.Image()

			// Clean up after build!
			var cleanupOnce sync.Once
			cleanupBuildContext = func() {
				cleanupOnce.Do(func() {
					for _, path := range []string{magicImageDest, envbuilderBinDest, magicTempDir.Path()} {
						if err := opts.Filesystem.Remove(path); err != nil {
							opts.Logger(log.LevelWarn, "failed to clean up magic temp dir from build context: %w", err)
						}
					}
				})
			}
			defer cleanupBuildContext()

			// Copy the envbuilder binary into the build context. External callers
			// will need to specify the path to the desired envbuilder binary.
			opts.Logger(log.LevelDebug, "copying envbuilder binary at %q to build context %q", opts.BinaryPath, envbuilderBinDest)
			if err := copyFile(opts.Filesystem, opts.BinaryPath, envbuilderBinDest, 0o755); err != nil {
				return fmt.Errorf("copy envbuilder binary to build context: %w", err)
			}

			// Also write the magic file that signifies the image has been built.
			// Since the user in the image is set to root, we also store the user
			// in the magic file to be used by envbuilder when the image is run.
			opts.Logger(log.LevelDebug, "writing magic image file at %q in build context %q", magicImageDest, magicTempDir)
			if err := writeMagicImageFile(opts.Filesystem, magicImageDest, runtimeData); err != nil {
				return fmt.Errorf("write magic image file in build context: %w", err)
			}
		}

		// temp move of all ro mounts
		tempRemountDest := workingDir.Join("mnt")
		// ignorePrefixes is a superset of ignorePaths that we pass to kaniko's
		// IgnoreList.
		ignorePrefixes := append([]string{"/dev", "/proc", "/sys"}, ignorePaths...)
		restoreMounts, err := ebutil.TempRemount(opts.Logger, tempRemountDest, ignorePrefixes...)
		defer func() { // restoreMounts should never be nil
			if err := restoreMounts(); err != nil {
				opts.Logger(log.LevelError, "restore mounts: %s", err.Error())
			}
		}()
		if err != nil {
			return fmt.Errorf("temp remount: %w", err)
		}

		stdoutWriter, closeStdout := log.Writer(opts.Logger)
		defer closeStdout()
		stderrWriter, closeStderr := log.Writer(opts.Logger)
		defer closeStderr()
		build := func() (v1.Image, error) {
			defer cleanupBuildContext()
			if runtimeData.Built && opts.SkipRebuild {
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
				runtimeData.Built = false
				runtimeData.SkippedRebuild = true
				return image, nil
			}

			// This is required for deleting the filesystem prior to build!
			err = util.InitIgnoreList()
			if err != nil {
				return nil, fmt.Errorf("init ignore list: %w", err)
			}

			// It's possible that the container will already have files in it, and
			// we don't want to merge a new container with the old one.
			if err := maybeDeleteFilesystem(opts.Logger, opts.ForceSafe); err != nil {
				return nil, fmt.Errorf("delete filesystem: %w", err)
			}

			cacheTTL := time.Hour * 24 * 7
			if opts.CacheTTLDays != 0 {
				cacheTTL = time.Hour * 24 * time.Duration(opts.CacheTTLDays)
			}

			// At this point we have all the context, we can now build!
			registryMirror := []string{}
			if val, ok := os.LookupEnv("KANIKO_REGISTRY_MIRROR"); ok {
				registryMirror = strings.Split(val, ";")
			}
			var destinations []string
			if opts.CacheRepo != "" {
				destinations = append(destinations, opts.CacheRepo)
			}
			kOpts := &config.KanikoOptions{
				// Boilerplate!
				CustomPlatform:     platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
				SnapshotMode:       "redo",
				RunV2:              true,
				RunStdout:          stdoutWriter,
				RunStderr:          stderrWriter,
				Destinations:       destinations,
				NoPush:             !opts.PushImage || len(destinations) == 0,
				CacheRunLayers:     true,
				CacheCopyLayers:    true,
				ForceBuildMetadata: opts.PushImage, // Force layers with no changes to be cached, required for cache probing.
				CompressedCaching:  true,
				Compression:        config.ZStd,
				// Maps to "default" level, ~100-300 MB/sec according to
				// benchmarks in klauspost/compress README
				// https://github.com/klauspost/compress/blob/67a538e2b4df11f8ec7139388838a13bce84b5d5/zstd/encoder_options.go#L188
				CompressionLevel: 3,
				CacheOptions: config.CacheOptions{
					CacheTTL: cacheTTL,
					CacheDir: opts.BaseImageCacheDir,
				},
				ForceUnpack:       true,
				BuildArgs:         buildParams.BuildArgs,
				CacheRepo:         opts.CacheRepo,
				Cache:             opts.CacheRepo != "" || opts.BaseImageCacheDir != "",
				DockerfilePath:    buildParams.DockerfilePath,
				DockerfileContent: buildParams.DockerfileContent,
				RegistryOptions: config.RegistryOptions{
					Insecure:      opts.Insecure,
					InsecurePull:  opts.Insecure,
					SkipTLSVerify: opts.Insecure,
					// Enables registry mirror features in Kaniko, see more in link below
					// https://github.com/GoogleContainerTools/kaniko?tab=readme-ov-file#flag---registry-mirror
					// Related to PR #114
					// https://github.com/coder/envbuilder/pull/114
					RegistryMirrors: registryMirror,
				},
				SrcContext: buildParams.BuildContext,

				// For cached image utilization, produce reproducible builds.
				Reproducible: opts.PushImage,
			}

			endStage := startStage("🏗️ Building image...")
			image, err := executor.DoBuild(kOpts)
			if err != nil {
				return nil, xerrors.Errorf("do build: %w", err)
			}
			endStage("🏗️ Built image!")
			if opts.PushImage {
				endStage = startStage("🏗️ Pushing image...")
				// To debug registry issues, enable logging:
				//
				// 	import (
				// 		stdlog "log"
				// 		reglogs "github.com/google/go-containerregistry/pkg/logs"
				// 	)
				// 	reglogs.Debug = stdlog.New(os.Stderr, "", 0)
				// 	reglogs.Warn = stdlog.New(os.Stderr, "", 0)
				// 	reglogs.Progress = stdlog.New(os.Stderr, "", 0)
				if err := executor.DoPush(image, kOpts); err == nil {
					endStage("🏗️ Pushed image!")
				} else if !opts.ExitOnPushFailure {
					endStage("⚠️️ Failed to push image!")
				} else {
					return nil, xerrors.Errorf("do push: %w", err)
				}
			}

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
				opts.Logger(log.LevelError, "Unable to pull the provided image. Ensure your registry credentials are correct!")
			}
			if !fallback || opts.ExitOnBuildFailure {
				return err
			}
			opts.Logger(log.LevelError, "Failed to build: %s", err)
			opts.Logger(log.LevelError, "Falling back to the default image...")
			buildParams, err = defaultBuildParams()
			if err != nil {
				return err
			}
			image, err = build()
		}
		if err != nil {
			return fmt.Errorf("build with kaniko: %w", err)
		}

		if err := restoreMounts(); err != nil {
			return fmt.Errorf("restore mounts: %w", err)
		}

		configFile, err := image.ConfigFile()
		if err != nil {
			return fmt.Errorf("get image config: %w", err)
		}

		runtimeData.ImageEnv = configFile.Config.Env

		// Dev Container metadata can be persisted through a standard label.
		// Note that this currently only works when we're building the image,
		// not when we're using a pre-built image as we don't have access to
		// labels.
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
			opts.Logger(log.LevelInfo, "#%d: 👀 Found devcontainer.json label metadata in image...", stageNumber)
			for _, container := range devContainer {
				if container.ContainerUser != "" {
					opts.Logger(log.LevelInfo, "#%d: 🧑 Updating the user to %q!", stageNumber, container.ContainerUser)

					configFile.Config.User = container.ContainerUser
				}
				maps.Copy(runtimeData.ContainerEnv, container.ContainerEnv)
				maps.Copy(runtimeData.RemoteEnv, container.RemoteEnv)
				if !container.OnCreateCommand.IsEmpty() {
					runtimeData.Scripts.OnCreateCommand = container.OnCreateCommand
				}
				if !container.UpdateContentCommand.IsEmpty() {
					runtimeData.Scripts.UpdateContentCommand = container.UpdateContentCommand
				}
				if !container.PostCreateCommand.IsEmpty() {
					runtimeData.Scripts.PostCreateCommand = container.PostCreateCommand
				}
				if !container.PostStartCommand.IsEmpty() {
					runtimeData.Scripts.PostStartCommand = container.PostStartCommand
				}
			}
		}

		maps.Copy(runtimeData.ContainerEnv, buildParams.ContainerEnv)
		maps.Copy(runtimeData.RemoteEnv, buildParams.RemoteEnv)
		if runtimeData.ContainerUser == "" && configFile.Config.User != "" {
			runtimeData.ContainerUser = configFile.Config.User
		}
	} else {
		runtimeData.DevcontainerPath, _, err = findDevcontainerJSON(opts.WorkspaceFolder, opts)
		if err == nil {
			file, err := opts.Filesystem.Open(runtimeData.DevcontainerPath)
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
				maps.Copy(runtimeData.ContainerEnv, devContainer.ContainerEnv)
				maps.Copy(runtimeData.RemoteEnv, devContainer.RemoteEnv)
				if devContainer.ContainerUser != "" {
					runtimeData.ContainerUser = devContainer.ContainerUser
				}
				runtimeData.Scripts = devContainer.LifecycleScripts
			} else {
				opts.Logger(log.LevelError, "Failed to parse devcontainer.json: %s", err.Error())
			}
		}
	}

	// Sanitize the environment of any opts!
	options.UnsetEnv()

	// Remove the Docker config secret file!
	if err := cleanupDockerConfigOverride(); err != nil {
		return err
	}

	// Set the environment from /etc/environment first, so it can be
	// overridden by the image and devcontainer settings.
	err = setEnvFromEtcEnvironment(opts.Logger)
	if err != nil {
		return fmt.Errorf("set env from /etc/environment: %w", err)
	}

	allEnvKeys := make(map[string]struct{})

	// It must be set in this parent process otherwise nothing will be found!
	for _, env := range runtimeData.ImageEnv {
		pair := strings.SplitN(env, "=", 2)
		os.Setenv(pair[0], pair[1])
		allEnvKeys[pair[0]] = struct{}{}
	}

	// Set Envbuilder runtime markers
	runtimeData.ContainerEnv["ENVBUILDER"] = "true"
	if runtimeData.DevcontainerPath != "" {
		runtimeData.ContainerEnv["DEVCONTAINER"] = "true"
		runtimeData.ContainerEnv["DEVCONTAINER_CONFIG"] = runtimeData.DevcontainerPath
	}

	for _, env := range []map[string]string{runtimeData.ContainerEnv, runtimeData.RemoteEnv} {
		envKeys := make([]string, 0, len(env))
		for key := range env {
			envKeys = append(envKeys, key)
			allEnvKeys[key] = struct{}{}
		}
		sort.Strings(envKeys)
		for _, envVar := range envKeys {
			value := devcontainer.SubstituteVars(env[envVar], opts.WorkspaceFolder, os.LookupEnv)
			os.Setenv(envVar, value)
		}
	}

	// Do not export env if we skipped a rebuild, because ENV directives
	// from the Dockerfile would not have been processed and we'd miss these
	// in the export. We should have generated a complete set of environment
	// on the intial build, so exporting environment variables a second time
	// isn't useful anyway.
	if opts.ExportEnvFile != "" && !runtimeData.SkippedRebuild {
		exportEnvFile, err := opts.Filesystem.Create(opts.ExportEnvFile)
		if err != nil {
			return fmt.Errorf("failed to open %s %q: %w", options.WithEnvPrefix("EXPORT_ENV_FILE"), opts.ExportEnvFile, err)
		}

		envKeys := make([]string, 0, len(allEnvKeys))
		for key := range allEnvKeys {
			envKeys = append(envKeys, key)
		}
		sort.Strings(envKeys)
		for _, key := range envKeys {
			fmt.Fprintf(exportEnvFile, "%s=%s\n", key, os.Getenv(key))
		}

		exportEnvFile.Close()
	}

	if runtimeData.ContainerUser == "" {
		opts.Logger(log.LevelWarn, "#%d: no user specified, using root", stageNumber)
	}
	execArgs.UserInfo, err = getUser(runtimeData.ContainerUser)
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
		if chownErr := filepath.Walk(opts.WorkspaceFolder, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, execArgs.UserInfo.uid, execArgs.UserInfo.gid)
		}); chownErr != nil {
			opts.Logger(log.LevelError, "chown %q: %s", execArgs.UserInfo.user.HomeDir, chownErr.Error())
			endStage("⚠️ Failed to the ownership of the workspace, you may need to fix this manually!")
		} else {
			endStage("👤 Updated the ownership of the workspace!")
		}
	}

	// We may also need to update the ownership of the user homedir.
	// Skip this step if the user is root.
	if execArgs.UserInfo.uid != 0 {
		endStage := startStage("🔄 Updating ownership of %s...", execArgs.UserInfo.user.HomeDir)
		if chownErr := filepath.Walk(execArgs.UserInfo.user.HomeDir, func(path string, _ fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, execArgs.UserInfo.uid, execArgs.UserInfo.gid)
		}); chownErr != nil {
			opts.Logger(log.LevelError, "chown %q: %s", execArgs.UserInfo.user.HomeDir, chownErr.Error())
			endStage("⚠️ Failed to update ownership of %s, you may need to fix this manually!", execArgs.UserInfo.user.HomeDir)
		} else {
			endStage("🏡 Updated ownership of %s!", execArgs.UserInfo.user.HomeDir)
		}
	}

	err = opts.Filesystem.MkdirAll(opts.WorkspaceFolder, 0o755)
	if err != nil {
		return fmt.Errorf("create workspace folder: %w", err)
	}
	err = os.Chdir(opts.WorkspaceFolder)
	if err != nil {
		return fmt.Errorf("change directory: %w", err)
	}

	// This is called before the Setuid to TARGET_USER because we want the
	// lifecycle scripts to run using the default user for the container,
	// rather than the user specified for running the init command. For
	// example, TARGET_USER may be set to root in the case where we will
	// exec systemd as the init command, but that doesn't mean we should
	// run the lifecycle scripts as root.
	os.Setenv("HOME", execArgs.UserInfo.user.HomeDir)
	if err := execLifecycleScripts(ctx, opts, runtimeData.Scripts, !runtimeData.Built, execArgs.UserInfo); err != nil {
		return err
	}

	// Create the magic file to indicate that this build
	// has already been ran before!
	if !runtimeData.Built {
		file, err := opts.Filesystem.Create(workingDir.Built())
		if err != nil {
			return fmt.Errorf("create magic file: %w", err)
		}
		_ = file.Close()
	}

	// The setup script can specify a custom initialization command
	// and arguments to run instead of the default shell.
	//
	// This is useful for hooking into the environment for a specific
	// init to PID 1.
	if opts.SetupScript != "" {
		// We execute the initialize script as the root user!
		os.Setenv("HOME", "/root")

		opts.Logger(log.LevelInfo, "=== Running the setup command %q as the root user...", opts.SetupScript)

		envKey := "ENVBUILDER_ENV"
		envFile := workingDir.Join("environ")
		file, err := opts.Filesystem.Create(envFile)
		if err != nil {
			return fmt.Errorf("create environ file: %w", err)
		}
		_ = file.Close()

		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", opts.SetupScript)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("%s=%s", envKey, envFile),
			fmt.Sprintf("TARGET_USER=%s", execArgs.UserInfo.user.Username),
		)
		cmd.Dir = opts.WorkspaceFolder
		// This allows for a really nice and clean experience to experiement with!
		// e.g. docker run --it --rm -e INIT_SCRIPT bash ...
		if isatty.IsTerminal(os.Stdout.Fd()) && isatty.IsTerminal(os.Stdin.Fd()) {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
		} else {
			cmd.Stdout = newWriteLogger(opts.Logger, log.LevelInfo)
			cmd.Stderr = newWriteLogger(opts.Logger, log.LevelError)
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
				execArgs.InitCommand = pair[1]
				updatedCommand = true
			case "INIT_ARGS":
				execArgs.InitArgs, err = shellquote.Split(pair[1])
				if err != nil {
					return fmt.Errorf("split init args: %w", err)
				}
				updatedArgs = true
			case "TARGET_USER":
				execArgs.UserInfo, err = getUser(pair[1])
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
			execArgs.InitArgs = []string{}
		}
	}

	// Hop into the user that should execute the initialize script!
	os.Setenv("HOME", execArgs.UserInfo.user.HomeDir)

	// Set last to ensure all environment changes are complete.
	execArgs.Environ = os.Environ()

	return nil
}

// RunCacheProbe performs a 'dry-run' build of the image and checks that
// all of the resulting layers are present in options.CacheRepo.
func RunCacheProbe(ctx context.Context, opts options.Options) (v1.Image, error) {
	defer options.UnsetEnv()
	if !opts.GetCachedImage {
		return nil, fmt.Errorf("developer error: RunCacheProbe must be run with --get-cached-image")
	}
	if opts.CacheRepo == "" {
		return nil, fmt.Errorf("--cache-repo must be set when using --get-cached-image")
	}

	workingDir := workingdir.At(opts.MagicDirBase)

	stageNumber := 0
	startStage := func(format string, args ...any) func(format string, args ...any) {
		now := time.Now()
		stageNumber++
		stageNum := stageNumber
		opts.Logger(log.LevelInfo, "#%d: %s", stageNum, fmt.Sprintf(format, args...))

		return func(format string, args ...any) {
			opts.Logger(log.LevelInfo, "#%d: %s [%s]", stageNum, fmt.Sprintf(format, args...), time.Since(now))
		}
	}

	opts.Logger(log.LevelInfo, "%s %s - Build development environments from repositories in a container", newColor(color.Bold).Sprintf("envbuilder"), buildinfo.Version())

	cleanupDockerConfigOverride, err := initDockerConfigOverride(opts.Filesystem, opts.Logger, workingDir, opts.DockerConfigBase64)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := cleanupDockerConfigOverride(); err != nil {
			opts.Logger(log.LevelError, "failed to cleanup docker config override: %w", err)
		}
	}() // best effort

	buildTimeWorkspaceFolder := opts.WorkspaceFolder
	var fallbackErr error
	var cloned bool
	if opts.GitURL != "" {
		endStage := startStage("📦 Cloning %s to %s...",
			newColor(color.FgCyan).Sprintf(opts.GitURL),
			newColor(color.FgCyan).Sprintf(opts.WorkspaceFolder),
		)
		stageNum := stageNumber
		logStage := func(format string, args ...any) {
			opts.Logger(log.LevelInfo, "#%d: %s", stageNum, fmt.Sprintf(format, args...))
		}

		// In cache probe mode we should only attempt to clone the full
		// repository if remote repo build mode isn't enabled.
		if !opts.RemoteRepoBuildMode {
			cloneOpts, err := git.CloneOptionsFromOptions(logStage, opts)
			if err != nil {
				return nil, fmt.Errorf("git clone options: %w", err)
			}

			w := git.ProgressWriter(logStage)
			defer w.Close()
			cloneOpts.Progress = w

			cloned, fallbackErr = git.CloneRepo(ctx, logStage, cloneOpts)
			if fallbackErr == nil {
				if cloned {
					endStage("📦 Cloned repository!")
				} else {
					endStage("📦 The repository already exists!")
				}
			} else {
				opts.Logger(log.LevelError, "Failed to clone repository: %s", fallbackErr.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}

			_ = w.Close()
		} else {
			cloneOpts, err := git.CloneOptionsFromOptions(logStage, opts)
			if err != nil {
				return nil, fmt.Errorf("git clone options: %w", err)
			}
			cloneOpts.Path = workingDir.Join("repo")

			endStage := startStage("📦 Remote repo build mode enabled, cloning %s to %s for build context...",
				newColor(color.FgCyan).Sprintf(opts.GitURL),
				newColor(color.FgCyan).Sprintf(cloneOpts.Path),
			)

			w := git.ProgressWriter(logStage)
			defer w.Close()
			cloneOpts.Progress = w

			fallbackErr = git.ShallowCloneRepo(ctx, logStage, cloneOpts)
			if fallbackErr == nil {
				endStage("📦 Cloned repository!")
				buildTimeWorkspaceFolder = cloneOpts.Path
			} else {
				opts.Logger(log.LevelError, "Failed to clone repository for remote repo mode: %s", fallbackErr.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}

			_ = w.Close()
		}
	}

	defaultBuildParams := func() (*devcontainer.Compiled, error) {
		dockerfile := workingDir.Join("Dockerfile")
		file, err := opts.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if opts.FallbackImage == "" {
			if fallbackErr != nil {
				return nil, fmt.Errorf("%s: %w", fallbackErr.Error(), ErrNoFallbackImage)
			}
			// We can't use errors.Join here because our tests
			// don't support parsing a multiline error.
			return nil, ErrNoFallbackImage
		}
		content := "FROM " + opts.FallbackImage
		_, err = file.Write([]byte(content))
		if err != nil {
			return nil, err
		}
		return &devcontainer.Compiled{
			DockerfilePath:    dockerfile,
			DockerfileContent: content,
			BuildContext:      workingDir.Path(),
		}, nil
	}

	var (
		buildParams      *devcontainer.Compiled
		devcontainerPath string
	)
	if opts.DockerfilePath == "" {
		// Only look for a devcontainer if a Dockerfile wasn't specified.
		// devcontainer is a standard, so it's reasonable to be the default.
		var devcontainerDir string
		var err error
		devcontainerPath, devcontainerDir, err = findDevcontainerJSON(buildTimeWorkspaceFolder, opts)
		if err != nil {
			opts.Logger(log.LevelError, "Failed to locate devcontainer.json: %s", err.Error())
			opts.Logger(log.LevelError, "Falling back to the default image...")
		} else {
			// We know a devcontainer exists.
			// Let's parse it and use it!
			file, err := opts.Filesystem.Open(devcontainerPath)
			if err != nil {
				return nil, fmt.Errorf("open devcontainer.json: %w", err)
			}
			defer file.Close()
			content, err := io.ReadAll(file)
			if err != nil {
				return nil, fmt.Errorf("read devcontainer.json: %w", err)
			}
			devContainer, err := devcontainer.Parse(content)
			if err == nil {
				var fallbackDockerfile string
				if !devContainer.HasImage() && !devContainer.HasDockerfile() {
					defaultParams, err := defaultBuildParams()
					if err != nil {
						return nil, fmt.Errorf("no Dockerfile or image found: %w", err)
					}
					opts.Logger(log.LevelInfo, "No Dockerfile or image specified; falling back to the default image...")
					fallbackDockerfile = defaultParams.DockerfilePath
				}
				buildParams, err = devContainer.Compile(opts.Filesystem, devcontainerDir, workingDir.Path(), fallbackDockerfile, opts.WorkspaceFolder, false, os.LookupEnv)
				if err != nil {
					return nil, fmt.Errorf("compile devcontainer.json: %w", err)
				}
			} else {
				opts.Logger(log.LevelError, "Failed to parse devcontainer.json: %s", err.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}
		}
	} else {
		// If a Dockerfile was specified, we use that.
		dockerfilePath := filepath.Join(buildTimeWorkspaceFolder, opts.DockerfilePath)

		// If the dockerfilePath is specified and deeper than the base of WorkspaceFolder AND the BuildContextPath is
		// not defined, show a warning
		dockerfileDir := filepath.Dir(dockerfilePath)
		if dockerfileDir != filepath.Clean(buildTimeWorkspaceFolder) && opts.BuildContextPath == "" {
			opts.Logger(log.LevelWarn, "given dockerfile %q is below %q and no custom build context has been defined", dockerfilePath, buildTimeWorkspaceFolder)
			opts.Logger(log.LevelWarn, "\t-> set BUILD_CONTEXT_PATH to %q to fix", dockerfileDir)
		}

		dockerfile, err := opts.Filesystem.Open(dockerfilePath)
		if err == nil {
			content, err := io.ReadAll(dockerfile)
			if err != nil {
				return nil, fmt.Errorf("read Dockerfile: %w", err)
			}
			buildParams = &devcontainer.Compiled{
				DockerfilePath:    dockerfilePath,
				DockerfileContent: string(content),
				BuildContext:      filepath.Join(buildTimeWorkspaceFolder, opts.BuildContextPath),
			}
		}
	}

	// When probing the build cache, there is no fallback!
	if buildParams == nil {
		return nil, fmt.Errorf("no Dockerfile or devcontainer.json found")
	}

	lvl := log.LevelInfo
	if opts.Verbose {
		lvl = log.LevelDebug
	}
	log.HijackLogrus(lvl, func(entry *logrus.Entry) {
		for _, line := range strings.Split(entry.Message, "\r") {
			opts.Logger(log.FromLogrus(entry.Level), "#%d: %s", stageNumber, color.HiBlackString(line))
		}
	})

	if opts.LayerCacheDir != "" {
		if opts.CacheRepo != "" {
			opts.Logger(log.LevelWarn, "Overriding cache repo with local registry...")
		}
		localRegistry, closeLocalRegistry, err := serveLocalRegistry(ctx, opts.Logger, opts.LayerCacheDir)
		if err != nil {
			return nil, err
		}
		defer closeLocalRegistry()
		opts.CacheRepo = localRegistry
	}

	// IgnorePaths in the Kaniko opts doesn't properly ignore paths.
	// So we add them to the default ignore list. See:
	// https://github.com/GoogleContainerTools/kaniko/blob/63be4990ca5a60bdf06ddc4d10aa4eca0c0bc714/cmd/executor/cmd/root.go#L136
	ignorePaths := append([]string{
		workingDir.Path(),
		opts.WorkspaceFolder,
		// See: https://github.com/coder/envbuilder/issues/37
		"/etc/resolv.conf",
	}, opts.IgnorePaths...)

	if opts.LayerCacheDir != "" {
		ignorePaths = append(ignorePaths, opts.LayerCacheDir)
	}

	for _, ignorePath := range ignorePaths {
		util.AddToDefaultIgnoreList(util.IgnoreListEntry{
			Path:            ignorePath,
			PrefixMatchOnly: false,
			AllowedPaths:    nil,
		})
	}

	// We expect an image built and pushed by envbuilder to have the envbuilder
	// binary present at a predefined path. In order to correctly replicate the
	// build via executor.RunCacheProbe we need to have the *exact* copy of the
	// envbuilder binary available used to build the image and we also need to
	// add the magic directives to the Dockerfile content.
	// WORKINGDIR
	buildParams.DockerfileContent += workingdir.Directives

	magicTempDir := filepath.Join(buildParams.BuildContext, workingdir.TempDir)
	if err := opts.Filesystem.MkdirAll(magicTempDir, 0o755); err != nil {
		return nil, fmt.Errorf("create magic temp dir in build context: %w", err)
	}
	envbuilderBinDest := filepath.Join(magicTempDir, "envbuilder")
	magicImageDest := filepath.Join(magicTempDir, "image")

	// Clean up after probe!
	defer func() {
		for _, path := range []string{magicImageDest, envbuilderBinDest, magicTempDir} {
			if err := opts.Filesystem.Remove(path); err != nil {
				opts.Logger(log.LevelWarn, "failed to clean up magic temp dir from build context: %w", err)
			}
		}
	}()

	// Copy the envbuilder binary into the build context. External callers
	// will need to specify the path to the desired envbuilder binary.
	opts.Logger(log.LevelDebug, "copying envbuilder binary at %q to build context %q", opts.BinaryPath, envbuilderBinDest)
	if err := copyFile(opts.Filesystem, opts.BinaryPath, envbuilderBinDest, 0o755); err != nil {
		return nil, xerrors.Errorf("copy envbuilder binary to build context: %w", err)
	}

	// Also write the magic file that signifies the image has been built.
	// Since the user in the image is set to root, we also store the user
	// in the magic file to be used by envbuilder when the image is run.
	opts.Logger(log.LevelDebug, "writing magic image file at %q in build context %q", magicImageDest, magicTempDir)
	runtimeData := runtimeDataStore{ContainerUser: buildParams.User}
	if err := writeMagicImageFile(opts.Filesystem, magicImageDest, runtimeData); err != nil {
		return nil, fmt.Errorf("write magic image file in build context: %w", err)
	}

	stdoutWriter, closeStdout := log.Writer(opts.Logger)
	defer closeStdout()
	stderrWriter, closeStderr := log.Writer(opts.Logger)
	defer closeStderr()
	cacheTTL := time.Hour * 24 * 7
	if opts.CacheTTLDays != 0 {
		cacheTTL = time.Hour * 24 * time.Duration(opts.CacheTTLDays)
	}

	// At this point we have all the context, we can now build!
	registryMirror := []string{}
	if val, ok := os.LookupEnv("KANIKO_REGISTRY_MIRROR"); ok {
		registryMirror = strings.Split(val, ";")
	}
	var destinations []string
	if opts.CacheRepo != "" {
		destinations = append(destinations, opts.CacheRepo)
	}
	kOpts := &config.KanikoOptions{
		// Boilerplate!
		CustomPlatform:     platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
		SnapshotMode:       "redo",
		RunV2:              true,
		RunStdout:          stdoutWriter,
		RunStderr:          stderrWriter,
		Destinations:       destinations,
		NoPush:             true,
		CacheRunLayers:     true,
		CacheCopyLayers:    true,
		ForceBuildMetadata: true, // Force layers with no changes to be cached, required for cache probing.
		CompressedCaching:  true,
		Compression:        config.ZStd,
		// Maps to "default" level, ~100-300 MB/sec according to
		// benchmarks in klauspost/compress README
		// https://github.com/klauspost/compress/blob/67a538e2b4df11f8ec7139388838a13bce84b5d5/zstd/encoder_options.go#L188
		CompressionLevel: 3,
		CacheOptions: config.CacheOptions{
			CacheTTL: cacheTTL,
			CacheDir: opts.BaseImageCacheDir,
		},
		ForceUnpack:       true,
		BuildArgs:         buildParams.BuildArgs,
		CacheRepo:         opts.CacheRepo,
		Cache:             opts.CacheRepo != "" || opts.BaseImageCacheDir != "",
		DockerfilePath:    buildParams.DockerfilePath,
		DockerfileContent: buildParams.DockerfileContent,
		RegistryOptions: config.RegistryOptions{
			Insecure:      opts.Insecure,
			InsecurePull:  opts.Insecure,
			SkipTLSVerify: opts.Insecure,
			// Enables registry mirror features in Kaniko, see more in link below
			// https://github.com/GoogleContainerTools/kaniko?tab=readme-ov-file#flag---registry-mirror
			// Related to PR #114
			// https://github.com/coder/envbuilder/pull/114
			RegistryMirrors: registryMirror,
		},
		SrcContext: buildParams.BuildContext,

		// When performing a cache probe, always perform reproducible snapshots.
		Reproducible: true,
	}

	endStage := startStage("🏗️ Checking for cached image...")
	image, err := executor.DoCacheProbe(kOpts)
	if err != nil {
		return nil, fmt.Errorf("get cached image: %w", err)
	}
	endStage("🏗️ Found cached image!")

	// Sanitize the environment of any opts!
	options.UnsetEnv()

	// Remove the Docker config secret file!
	if err := cleanupDockerConfigOverride(); err != nil {
		return nil, err
	}

	return image, nil
}

func setEnvFromEtcEnvironment(logf log.Func) error {
	environ, err := os.ReadFile("/etc/environment")
	if errors.Is(err, os.ErrNotExist) {
		logf(log.LevelDebug, "Not loading environment from /etc/environment, file does not exist")
		return nil
	}
	if err != nil {
		return err
	}
	for _, env := range strings.Split(string(environ), "\n") {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) != 2 {
			continue
		}
		os.Setenv(pair[0], pair[1])
	}
	return nil
}

type userInfo struct {
	uid  int
	gid  int
	user *user.User
}

func getUser(username string) (userInfo, error) {
	user, err := findUser(username)
	if err != nil {
		return userInfo{}, fmt.Errorf("find user: %w", err)
	}
	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return userInfo{}, fmt.Errorf("parse uid: %w", err)
	}
	gid, err := strconv.Atoi(user.Gid)
	if err != nil {
		return userInfo{}, fmt.Errorf("parse gid: %w", err)
	}
	if user.Username == "" && uid == 0 {
		// This is nice for the visual display in log messages,
		// but has no actual functionality since the credential
		// in the syscall is what matters.
		user.Username = "root"
		user.HomeDir = "/root"
	}
	return userInfo{
		uid:  uid,
		gid:  gid,
		user: user,
	}, nil
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

func execOneLifecycleScript(
	ctx context.Context,
	logf func(level log.Level, format string, args ...any),
	s devcontainer.LifecycleScript,
	scriptName string,
	userInfo userInfo,
) error {
	if s.IsEmpty() {
		return nil
	}
	logf(log.LevelInfo, "=== Running %s as the %q user...", scriptName, userInfo.user.Username)
	if err := s.Execute(ctx, userInfo.uid, userInfo.gid); err != nil {
		logf(log.LevelError, "Failed to run %s: %v", scriptName, err)
		return err
	}
	return nil
}

func execLifecycleScripts(
	ctx context.Context,
	options options.Options,
	scripts devcontainer.LifecycleScripts,
	firstStart bool,
	userInfo userInfo,
) error {
	if options.PostStartScriptPath != "" {
		_ = os.Remove(options.PostStartScriptPath)
	}

	if firstStart {
		if err := execOneLifecycleScript(ctx, options.Logger, scripts.OnCreateCommand, "onCreateCommand", userInfo); err != nil {
			// skip remaining lifecycle commands
			return nil
		}
	}
	if err := execOneLifecycleScript(ctx, options.Logger, scripts.UpdateContentCommand, "updateContentCommand", userInfo); err != nil {
		// skip remaining lifecycle commands
		return nil
	}
	if err := execOneLifecycleScript(ctx, options.Logger, scripts.PostCreateCommand, "postCreateCommand", userInfo); err != nil {
		// skip remaining lifecycle commands
		return nil
	}
	if !scripts.PostStartCommand.IsEmpty() {
		// If PostStartCommandPath is set, the init command is responsible
		// for running the postStartCommand. Otherwise, we execute it now.
		if options.PostStartScriptPath != "" {
			if err := createPostStartScript(options.PostStartScriptPath, scripts.PostStartCommand); err != nil {
				return fmt.Errorf("failed to create post-start script: %w", err)
			}
		} else {
			_ = execOneLifecycleScript(ctx, options.Logger, scripts.PostStartCommand, "postStartCommand", userInfo)
		}
	}
	return nil
}

func createPostStartScript(path string, postStartCommand devcontainer.LifecycleScript) error {
	postStartScript, err := os.Create(path)
	if err != nil {
		return err
	}
	defer postStartScript.Close()

	if err := postStartScript.Chmod(0o755); err != nil {
		return err
	}

	if _, err := postStartScript.WriteString("#!/bin/sh\n\n" + postStartCommand.ScriptLines()); err != nil {
		return err
	}
	return nil
}

func newColor(value ...color.Attribute) *color.Color {
	c := color.New(value...)
	c.EnableColor()
	return c
}

func findDevcontainerJSON(workspaceFolder string, options options.Options) (string, string, error) {
	if workspaceFolder == "" {
		workspaceFolder = options.WorkspaceFolder
	}

	// 0. Check if custom devcontainer directory or path is provided.
	if options.DevcontainerDir != "" || options.DevcontainerJSONPath != "" {
		devcontainerDir := options.DevcontainerDir
		if devcontainerDir == "" {
			devcontainerDir = ".devcontainer"
		}

		// If `devcontainerDir` is not an absolute path, assume it is relative to the workspace folder.
		if !filepath.IsAbs(devcontainerDir) {
			devcontainerDir = filepath.Join(workspaceFolder, devcontainerDir)
		}

		// An absolute location always takes a precedence.
		devcontainerPath := options.DevcontainerJSONPath
		if filepath.IsAbs(devcontainerPath) {
			return options.DevcontainerJSONPath, devcontainerDir, nil
		}
		// If an override is not provided, assume it is just `devcontainer.json`.
		if devcontainerPath == "" {
			devcontainerPath = "devcontainer.json"
		}

		if !filepath.IsAbs(devcontainerPath) {
			devcontainerPath = filepath.Join(devcontainerDir, devcontainerPath)
		}
		return devcontainerPath, devcontainerDir, nil
	}

	// 1. Check `workspaceFolder`/.devcontainer/devcontainer.json.
	location := filepath.Join(workspaceFolder, ".devcontainer", "devcontainer.json")
	if _, err := options.Filesystem.Stat(location); err == nil {
		return location, filepath.Dir(location), nil
	}

	// 2. Check `workspaceFolder`/devcontainer.json.
	location = filepath.Join(workspaceFolder, "devcontainer.json")
	if _, err := options.Filesystem.Stat(location); err == nil {
		return location, filepath.Dir(location), nil
	}

	// 3. Check every folder: `workspaceFolder`/.devcontainer/<folder>/devcontainer.json.
	devcontainerDir := filepath.Join(workspaceFolder, ".devcontainer")

	fileInfos, err := options.Filesystem.ReadDir(devcontainerDir)
	if err != nil {
		return "", "", err
	}

	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() {
			options.Logger(log.LevelDebug, `%s is a file`, fileInfo.Name())
			continue
		}

		location := filepath.Join(devcontainerDir, fileInfo.Name(), "devcontainer.json")
		if _, err := options.Filesystem.Stat(location); err != nil {
			options.Logger(log.LevelDebug, `stat %s failed: %s`, location, err.Error())
			continue
		}

		return location, filepath.Dir(location), nil
	}

	return "", "", errors.New("can't find devcontainer.json, is it a correct spec?")
}

// maybeDeleteFilesystem wraps util.DeleteFilesystem with a guard to hopefully stop
// folks from unwittingly deleting their entire root directory.
func maybeDeleteFilesystem(logger log.Func, force bool) error {
	// We always expect the magic directory to be set to the default, signifying that
	// the user is running envbuilder in a container.
	// If this is set to anything else we should bail out to prevent accidental data loss.
	// defaultWorkingDir := workingdir.WorkingDir("")
	kanikoDir, ok := os.LookupEnv("KANIKO_DIR")
	if !ok || strings.TrimSpace(kanikoDir) != workingdir.Default.Path() {
		if !force {
			logger(log.LevelError, "KANIKO_DIR is not set to %s. Bailing!\n", workingdir.Default.Path())
			logger(log.LevelError, "To bypass this check, set FORCE_SAFE=true.")
			return errors.New("safety check failed")
		}
		bailoutSecs := 10
		logger(log.LevelWarn, "WARNING! BYPASSING SAFETY CHECK! THIS WILL DELETE YOUR ROOT FILESYSTEM!")
		logger(log.LevelWarn, "You have %d seconds to bail out!", bailoutSecs)
		for i := bailoutSecs; i > 0; i-- {
			logger(log.LevelWarn, "%d...", i)
			<-time.After(time.Second)
		}
	}

	return util.DeleteFilesystem()
}

func fileExists(fs billy.Filesystem, path string) bool {
	fi, err := fs.Stat(path)
	return err == nil && !fi.IsDir()
}

func readFile(fs billy.Filesystem, name string) ([]byte, error) {
	f, err := fs.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return b, nil
}

func copyFile(fs billy.Filesystem, src, dst string, mode fs.FileMode) error {
	srcF, err := fs.Open(src)
	if err != nil {
		return fmt.Errorf("open src file: %w", err)
	}
	defer srcF.Close()

	err = fs.MkdirAll(filepath.Dir(dst), mode)
	if err != nil {
		return fmt.Errorf("create destination dir failed: %w", err)
	}

	dstF, err := fs.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("open dest file for writing: %w", err)
	}
	defer dstF.Close()

	if _, err := io.Copy(dstF, srcF); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}
	return nil
}

func writeFile(fs billy.Filesystem, name string, data []byte, perm fs.FileMode) error {
	f, err := fs.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	_, err = f.Write(data)
	if err != nil {
		err = fmt.Errorf("write file: %w", err)
	}
	if err2 := f.Close(); err2 != nil && err == nil {
		err = fmt.Errorf("close file: %w", err2)
	}
	return err
}

func writeMagicImageFile(fs billy.Filesystem, path string, v any) error {
	file, err := fs.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create magic image file: %w", err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode magic image file: %w", err)
	}

	return nil
}

func parseMagicImageFile(fs billy.Filesystem, path string, v any) error {
	file, err := fs.Open(path)
	if err != nil {
		return fmt.Errorf("open magic image file: %w", err)
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode magic image file: %w", err)
	}

	return nil
}

const (
	dockerConfigFile   = dockerconfig.ConfigFileName
	dockerConfigEnvKey = dockerconfig.EnvOverrideConfigDir
)

// initDockerConfigOverride sets the DOCKER_CONFIG environment variable
// to a path within the working directory. If a base64 encoded Docker
// config is provided, it is written to the path/config.json and the
// DOCKER_CONFIG environment variable is set to the path. If no base64
// encoded Docker config is provided, the following paths are checked in
// order:
//
// 1. $DOCKER_CONFIG/config.json
// 2. $DOCKER_CONFIG
// 3. /.envbuilder/config.json
//
// If a Docker config file is found, its path is set as DOCKER_CONFIG.
func initDockerConfigOverride(bfs billy.Filesystem, logf log.Func, workingDir workingdir.WorkingDir, dockerConfigBase64 string) (func() error, error) {
	// If dockerConfigBase64 is set, it will have priority over file
	// detection.
	var dockerConfigJSON []byte
	var err error
	if dockerConfigBase64 != "" {
		logf(log.LevelInfo, "Using base64 encoded Docker config")

		dockerConfigJSON, err = base64.StdEncoding.DecodeString(dockerConfigBase64)
		if err != nil {
			return nil, fmt.Errorf("decode docker config: %w", err)
		}
	}

	oldDockerConfig := os.Getenv(dockerConfigEnvKey)
	var oldDockerConfigFile string
	if oldDockerConfig != "" {
		oldDockerConfigFile = filepath.Join(oldDockerConfig, dockerConfigFile)
	}
	for _, path := range []string{
		oldDockerConfigFile,               // $DOCKER_CONFIG/config.json
		oldDockerConfig,                   // $DOCKER_CONFIG
		workingDir.Join(dockerConfigFile), // /.envbuilder/config.json
	} {
		if path == "" || !fileExists(bfs, path) {
			continue
		}

		logf(log.LevelWarn, "Found Docker config at %s, this file will remain after the build", path)

		if dockerConfigJSON == nil {
			logf(log.LevelInfo, "Using Docker config at %s", path)

			dockerConfigJSON, err = readFile(bfs, path)
			if err != nil {
				return nil, fmt.Errorf("read docker config: %w", err)
			}
		} else {
			logf(log.LevelWarn, "Ignoring Docker config at %s, using base64 encoded Docker config instead", path)
		}
		break
	}

	if dockerConfigJSON == nil {
		// No user-provided config available.
		return func() error { return nil }, nil
	}

	dockerConfigJSON, err = hujson.Standardize(dockerConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("humanize json for docker config: %w", err)
	}

	if err = logDockerAuthConfigs(logf, dockerConfigJSON); err != nil {
		return nil, fmt.Errorf("log docker auth configs: %w", err)
	}

	// We're going to set the DOCKER_CONFIG environment variable to a
	// path within the working directory so that Kaniko can pick it up.
	// A user should not mount a file directly to this path as we will
	// write to the file.
	newDockerConfig := workingDir.Join(".docker")
	newDockerConfigFile := filepath.Join(newDockerConfig, dockerConfigFile)
	err = bfs.MkdirAll(newDockerConfig, 0o700)
	if err != nil {
		return nil, fmt.Errorf("create docker config dir: %w", err)
	}

	if fileExists(bfs, newDockerConfigFile) {
		return nil, fmt.Errorf("unable to write Docker config file, file already exists: %s", newDockerConfigFile)
	}

	restoreEnv, err := setAndRestoreEnv(logf, dockerConfigEnvKey, newDockerConfig)
	if err != nil {
		return nil, fmt.Errorf("set docker config override: %w", err)
	}

	err = writeFile(bfs, newDockerConfigFile, dockerConfigJSON, 0o600)
	if err != nil {
		_ = restoreEnv() // Best effort.
		return nil, fmt.Errorf("write docker config: %w", err)
	}
	logf(log.LevelInfo, "Wrote Docker config JSON to %s", newDockerConfigFile)

	cleanupFile := onceErrFunc(func() error {
		// Remove the Docker config secret file!
		if err := bfs.Remove(newDockerConfigFile); err != nil {
			logf(log.LevelError, "Failed to remove the Docker config secret file: %s", err)
			return fmt.Errorf("remove docker config: %w", err)
		}
		return nil
	})
	return func() error { return errors.Join(cleanupFile(), restoreEnv()) }, nil
}

func logDockerAuthConfigs(logf log.Func, dockerConfigJSON []byte) error {
	dc := new(DockerConfig)
	err := dc.LoadFromReader(bytes.NewReader(dockerConfigJSON))
	if err != nil {
		return fmt.Errorf("load docker config: %w", err)
	}
	for k := range dc.AuthConfigs {
		logf(log.LevelInfo, "Docker config contains auth for registry %q", k)
	}
	return nil
}

func setAndRestoreEnv(logf log.Func, key, value string) (restore func() error, err error) {
	old := os.Getenv(key)
	err = os.Setenv(key, value)
	if err != nil {
		logf(log.LevelError, "Failed to set %s: %s", key, err)
		return nil, fmt.Errorf("set %s: %w", key, err)
	}
	logf(log.LevelInfo, "Set %s to %s", key, value)
	return onceErrFunc(func() error {
		if err := func() error {
			if old == "" {
				return os.Unsetenv(key)
			}
			return os.Setenv(key, old)
		}(); err != nil {
			return fmt.Errorf("restore %s: %w", key, err)
		}
		logf(log.LevelInfo, "Restored %s to %s", key, old)
		return nil
	}), nil
}

func onceErrFunc(f func() error) func() error {
	var once sync.Once
	return func() error {
		var err error
		once.Do(func() {
			err = f()
		})
		return err
	}
}

type writeLogger struct {
	logf  log.Func
	level log.Level
}

func newWriteLogger(logf log.Func, level log.Level) io.Writer {
	return writeLogger{logf: logf, level: level}
}

func (l writeLogger) Write(p []byte) (n int, err error) {
	lines := bytes.Split(p, []byte("\n"))
	for _, line := range lines {
		l.logf(l.level, "%s", line)
	}
	return len(p), nil
}

// Allows quick testing of layer caching using a local directory!
func serveLocalRegistry(ctx context.Context, logf log.Func, layerCacheDir string) (string, func(), error) {
	noop := func() {}
	if layerCacheDir == "" {
		return "", noop, nil
	}
	cfg := &configuration.Configuration{
		Storage: configuration.Storage{
			"filesystem": configuration.Parameters{
				"rootdirectory": layerCacheDir,
			},
		},
	}
	cfg.Log.Level = "error"

	// Spawn an in-memory registry to cache built layers...
	registry := handlers.NewApp(ctx, cfg)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("start listener for in-memory registry: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return "", noop, fmt.Errorf("listener addr was of wrong type: %T", listener.Addr())
	}
	srv := &http.Server{
		Handler: registry,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := srv.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf(log.LevelError, "Failed to serve registry: %s", err.Error())
		}
	}()
	var closeOnce sync.Once
	closer := func() {
		closeOnce.Do(func() {
			_ = srv.Close()
			_ = listener.Close()
			<-done
		})
	}
	addr := fmt.Sprintf("localhost:%d/local/cache", tcpAddr.Port)
	return addr, closer, nil
}
