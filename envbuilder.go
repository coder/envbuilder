package envbuilder

import (
	"bufio"
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

	"github.com/coder/envbuilder/constants"
	"github.com/coder/envbuilder/git"
	"github.com/coder/envbuilder/options"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/creds"
	"github.com/GoogleContainerTools/kaniko/pkg/executor"
	"github.com/GoogleContainerTools/kaniko/pkg/util"
	"github.com/coder/envbuilder/devcontainer"
	"github.com/coder/envbuilder/internal/ebutil"
	"github.com/coder/envbuilder/log"
	"github.com/containerd/containerd/platforms"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
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

// DockerConfig represents the Docker configuration file.
type DockerConfig configfile.ConfigFile

// Run runs the envbuilder.
// Logger is the logf to use for all operations.
// Filesystem is the filesystem to use for all operations.
// Defaults to the host filesystem.
func Run(ctx context.Context, opts options.Options) error {
	defer options.UnsetEnv()
	if opts.GetCachedImage {
		return fmt.Errorf("developer error: use RunCacheProbe instead")
	}

	if opts.CacheRepo == "" && opts.PushImage {
		return fmt.Errorf("--cache-repo must be set when using --push-image")
	}
	// Default to the shell!
	initArgs := []string{"-c", opts.InitScript}
	if opts.InitArgs != "" {
		var err error
		initArgs, err = shellquote.Split(opts.InitArgs)
		if err != nil {
			return fmt.Errorf("parse init args: %w", err)
		}
	}

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

	opts.Logger(log.LevelInfo, "%s - Build development environments from repositories in a container", newColor(color.Bold).Sprintf("envbuilder"))

	cleanupDockerConfigJSON, err := initDockerConfigJSON(opts.DockerConfigBase64)
	if err != nil {
		return err
	}
	defer func() {
		if err := cleanupDockerConfigJSON(); err != nil {
			opts.Logger(log.LevelError, "failed to cleanup docker config JSON: %w", err)
		}
	}() // best effort

	buildTimeWorkspaceFolder := opts.WorkspaceFolder
	var fallbackErr error
	var cloned bool
	if opts.GitURL != "" {
		cloneOpts, err := git.CloneOptionsFromOptions(opts)
		if err != nil {
			return fmt.Errorf("git clone options: %w", err)
		}

		endStage := startStage("📦 Cloning %s to %s...",
			newColor(color.FgCyan).Sprintf(opts.GitURL),
			newColor(color.FgCyan).Sprintf(cloneOpts.Path),
		)

		w := git.ProgressWriter(func(line string) { opts.Logger(log.LevelInfo, "#%d: %s", stageNumber, line) })
		defer w.Close()
		cloneOpts.Progress = w

		cloned, fallbackErr = git.CloneRepo(ctx, cloneOpts)
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

		// Always clone the repo in remote repo build mode into a location that
		// we control that isn't affected by the users changes.
		if opts.RemoteRepoBuildMode {
			cloneOpts, err := git.CloneOptionsFromOptions(opts)
			if err != nil {
				return fmt.Errorf("git clone options: %w", err)
			}
			cloneOpts.Path = constants.MagicRemoteRepoDir

			endStage := startStage("📦 Remote repo build mode enabled, cloning %s to %s for build context...",
				newColor(color.FgCyan).Sprintf(opts.GitURL),
				newColor(color.FgCyan).Sprintf(cloneOpts.Path),
			)

			w := git.ProgressWriter(func(line string) { opts.Logger(log.LevelInfo, "#%d: %s", stageNumber, line) })
			defer w.Close()
			cloneOpts.Progress = w

			fallbackErr = git.ShallowCloneRepo(ctx, cloneOpts)
			if fallbackErr == nil {
				endStage("📦 Cloned repository!")
				buildTimeWorkspaceFolder = cloneOpts.Path
			} else {
				opts.Logger(log.LevelError, "Failed to clone repository for remote repo mode: %s", fallbackErr.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}
		}
	}

	defaultBuildParams := func() (*devcontainer.Compiled, error) {
		dockerfile := filepath.Join(constants.MagicDir, "Dockerfile")
		file, err := opts.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if opts.FallbackImage == "" {
			if fallbackErr != nil {
				return nil, xerrors.Errorf("%s: %w", fallbackErr.Error(), constants.ErrNoFallbackImage)
			}
			// We can't use errors.Join here because our tests
			// don't support parsing a multiline error.
			return nil, constants.ErrNoFallbackImage
		}
		content := "FROM " + opts.FallbackImage
		_, err = file.Write([]byte(content))
		if err != nil {
			return nil, err
		}
		return &devcontainer.Compiled{
			DockerfilePath:    dockerfile,
			DockerfileContent: content,
			BuildContext:      constants.MagicDir,
		}, nil
	}

	var (
		buildParams *devcontainer.Compiled
		scripts     devcontainer.LifecycleScripts

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
				buildParams, err = devContainer.Compile(opts.Filesystem, devcontainerDir, constants.MagicDir, fallbackDockerfile, opts.WorkspaceFolder, false, os.LookupEnv)
				if err != nil {
					return fmt.Errorf("compile devcontainer.json: %w", err)
				}
				scripts = devContainer.LifecycleScripts
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

	HijackLogrus(func(entry *logrus.Entry) {
		for _, line := range strings.Split(entry.Message, "\r") {
			opts.Logger(log.LevelInfo, "#%d: %s", stageNumber, color.HiBlackString(line))
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
		constants.MagicDir,
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
		if err := util.AddAllowedPathToDefaultIgnoreList(constants.MagicImage); err != nil {
			return fmt.Errorf("add magic image file to ignore list: %w", err)
		}
		// Add the magic directives that embed the binary into the built image.
		buildParams.DockerfileContent += constants.MagicDirectives
		// Copy the envbuilder binary into the build context.
		// External callers will need to specify the path to the desired envbuilder binary.
		envbuilderBinDest := filepath.Join(buildParams.BuildContext, filepath.Base(constants.MagicBinaryLocation))
		opts.Logger(log.LevelDebug, "copying envbuilder binary at %q to build context %q", opts.BinaryPath, buildParams.BuildContext)
		if err := copyFile(opts.BinaryPath, envbuilderBinDest, 0o755); err != nil {
			return fmt.Errorf("copy envbuilder binary to build context: %w", err)
		}

		// Also touch the magic file that signifies the image has been built!
		magicImageDest := filepath.Join(buildParams.BuildContext, filepath.Base(constants.MagicImage))
		opts.Logger(log.LevelDebug, "copying envbuilder binary at %q to build context %q", opts.BinaryPath, buildParams.BuildContext)
		if err := touchFile(magicImageDest, 0o755); err != nil {
			return fmt.Errorf("copy envbuilder binary to build context: %w", err)
		}

		// Clean up after build!
		cleanupBuildContext = func() {
			if err := os.Remove(envbuilderBinDest); err != nil {
				opts.Logger(log.LevelWarn, "failed to clean up envbuilder binary from build context: %w", err)
			}
			if err := os.Remove(magicImageDest); err != nil {
				opts.Logger(log.LevelWarn, "failed to clean up magic image file from build context: %w", err)
			}
		}
		defer cleanupBuildContext()
	}

	// temp move of all ro mounts
	tempRemountDest := filepath.Join("/", constants.MagicDir, "mnt")
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

	skippedRebuild := false
	stdoutWriter, closeStdout := log.Writer(opts.Logger)
	defer closeStdout()
	stderrWriter, closeStderr := log.Writer(opts.Logger)
	defer closeStderr()
	build := func() (v1.Image, error) {
		defer cleanupBuildContext()
		_, alreadyBuiltErr := opts.Filesystem.Stat(constants.MagicFile)
		_, isImageErr := opts.Filesystem.Stat(constants.MagicImage)
		if (alreadyBuiltErr == nil && opts.SkipRebuild) || isImageErr == nil {
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
			skippedRebuild = true
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
			CustomPlatform:    platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
			SnapshotMode:      "redo",
			RunV2:             true,
			RunStdout:         stdoutWriter,
			RunStderr:         stderrWriter,
			Destinations:      destinations,
			NoPush:            !opts.PushImage || len(destinations) == 0,
			CacheRunLayers:    true,
			CacheCopyLayers:   true,
			CompressedCaching: true,
			Compression:       config.ZStd,
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
			if err := executor.DoPush(image, kOpts); err != nil {
				return nil, xerrors.Errorf("do push: %w", err)
			}
			endStage("🏗️ Pushed image!")
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

	// Create the magic file to indicate that this build
	// has already been ran before!
	file, err := opts.Filesystem.Create(constants.MagicFile)
	if err != nil {
		return fmt.Errorf("create magic file: %w", err)
	}
	_ = file.Close()

	configFile, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("get image config: %w", err)
	}

	containerEnv := make(map[string]string)
	remoteEnv := make(map[string]string)

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
		opts.Logger(log.LevelInfo, "#%d: 👀 Found devcontainer.json label metadata in image...", stageNumber)
		for _, container := range devContainer {
			if container.RemoteUser != "" {
				opts.Logger(log.LevelInfo, "#%d: 🧑 Updating the user to %q!", stageNumber, container.RemoteUser)

				configFile.Config.User = container.RemoteUser
			}
			maps.Copy(containerEnv, container.ContainerEnv)
			maps.Copy(remoteEnv, container.RemoteEnv)
			if !container.OnCreateCommand.IsEmpty() {
				scripts.OnCreateCommand = container.OnCreateCommand
			}
			if !container.UpdateContentCommand.IsEmpty() {
				scripts.UpdateContentCommand = container.UpdateContentCommand
			}
			if !container.PostCreateCommand.IsEmpty() {
				scripts.PostCreateCommand = container.PostCreateCommand
			}
			if !container.PostStartCommand.IsEmpty() {
				scripts.PostStartCommand = container.PostStartCommand
			}
		}
	}

	// Sanitize the environment of any opts!
	options.UnsetEnv()

	// Remove the Docker config secret file!
	if err := cleanupDockerConfigJSON(); err != nil {
		return err
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

	allEnvKeys := make(map[string]struct{})

	// It must be set in this parent process otherwise nothing will be found!
	for _, env := range configFile.Config.Env {
		pair := strings.SplitN(env, "=", 2)
		os.Setenv(pair[0], pair[1])
		allEnvKeys[pair[0]] = struct{}{}
	}
	maps.Copy(containerEnv, buildParams.ContainerEnv)
	maps.Copy(remoteEnv, buildParams.RemoteEnv)

	// Set Envbuilder runtime markers
	containerEnv["ENVBUILDER"] = "true"
	if devcontainerPath != "" {
		containerEnv["DEVCONTAINER"] = "true"
		containerEnv["DEVCONTAINER_CONFIG"] = devcontainerPath
	}

	for _, env := range []map[string]string{containerEnv, remoteEnv} {
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
	if opts.ExportEnvFile != "" && !skippedRebuild {
		exportEnvFile, err := os.Create(opts.ExportEnvFile)
		if err != nil {
			return fmt.Errorf("failed to open EXPORT_ENV_FILE %q: %w", opts.ExportEnvFile, err)
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

	username := configFile.Config.User
	if buildParams.User != "" {
		username = buildParams.User
	}
	if username == "" {
		opts.Logger(log.LevelWarn, "#%d: no user specified, using root", stageNumber)
	}

	userInfo, err := getUser(username)
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
			return os.Chown(path, userInfo.uid, userInfo.gid)
		}); chownErr != nil {
			opts.Logger(log.LevelError, "chown %q: %s", userInfo.user.HomeDir, chownErr.Error())
			endStage("⚠️ Failed to the ownership of the workspace, you may need to fix this manually!")
		} else {
			endStage("👤 Updated the ownership of the workspace!")
		}
	}

	// We may also need to update the ownership of the user homedir.
	// Skip this step if the user is root.
	if userInfo.uid != 0 {
		endStage := startStage("🔄 Updating ownership of %s...", userInfo.user.HomeDir)
		if chownErr := filepath.Walk(userInfo.user.HomeDir, func(path string, _ fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, userInfo.uid, userInfo.gid)
		}); chownErr != nil {
			opts.Logger(log.LevelError, "chown %q: %s", userInfo.user.HomeDir, chownErr.Error())
			endStage("⚠️ Failed to update ownership of %s, you may need to fix this manually!", userInfo.user.HomeDir)
		} else {
			endStage("🏡 Updated ownership of %s!", userInfo.user.HomeDir)
		}
	}

	err = os.MkdirAll(opts.WorkspaceFolder, 0o755)
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
	os.Setenv("HOME", userInfo.user.HomeDir)
	if err := execLifecycleScripts(ctx, opts, scripts, skippedRebuild, userInfo); err != nil {
		return err
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
		envFile := filepath.Join("/", constants.MagicDir, "environ")
		file, err := os.Create(envFile)
		if err != nil {
			return fmt.Errorf("create environ file: %w", err)
		}
		_ = file.Close()

		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", opts.SetupScript)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("%s=%s", envKey, envFile),
			fmt.Sprintf("TARGET_USER=%s", userInfo.user.Username),
		)
		cmd.Dir = opts.WorkspaceFolder
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
					opts.Logger(log.LevelInfo, "%s", scanner.Text())
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
				opts.InitCommand = pair[1]
				updatedCommand = true
			case "INIT_ARGS":
				initArgs, err = shellquote.Split(pair[1])
				if err != nil {
					return fmt.Errorf("split init args: %w", err)
				}
				updatedArgs = true
			case "TARGET_USER":
				userInfo, err = getUser(pair[1])
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
	os.Setenv("HOME", userInfo.user.HomeDir)

	err = syscall.Setgid(userInfo.gid)
	if err != nil {
		return fmt.Errorf("set gid: %w", err)
	}
	err = syscall.Setuid(userInfo.uid)
	if err != nil {
		return fmt.Errorf("set uid: %w", err)
	}

	opts.Logger(log.LevelInfo, "=== Running the init command %s %+v as the %q user...", opts.InitCommand, initArgs, userInfo.user.Username)

	err = syscall.Exec(opts.InitCommand, append([]string{opts.InitCommand}, initArgs...), os.Environ())
	if err != nil {
		return fmt.Errorf("exec init script: %w", err)
	}
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

	opts.Logger(log.LevelInfo, "%s - Build development environments from repositories in a container", newColor(color.Bold).Sprintf("envbuilder"))

	cleanupDockerConfigJSON, err := initDockerConfigJSON(opts.DockerConfigBase64)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := cleanupDockerConfigJSON(); err != nil {
			opts.Logger(log.LevelError, "failed to cleanup docker config JSON: %w", err)
		}
	}() // best effort

	buildTimeWorkspaceFolder := opts.WorkspaceFolder
	var fallbackErr error
	var cloned bool
	if opts.GitURL != "" {
		// In cache probe mode we should only attempt to clone the full
		// repository if remote repo build mode isn't enabled.
		if !opts.RemoteRepoBuildMode {
			cloneOpts, err := git.CloneOptionsFromOptions(opts)
			if err != nil {
				return nil, fmt.Errorf("git clone options: %w", err)
			}

			endStage := startStage("📦 Cloning %s to %s...",
				newColor(color.FgCyan).Sprintf(opts.GitURL),
				newColor(color.FgCyan).Sprintf(cloneOpts.Path),
			)

			w := git.ProgressWriter(func(line string) { opts.Logger(log.LevelInfo, "#%d: %s", stageNumber, line) })
			defer w.Close()
			cloneOpts.Progress = w

			cloned, fallbackErr = git.CloneRepo(ctx, cloneOpts)
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
		} else {
			cloneOpts, err := git.CloneOptionsFromOptions(opts)
			if err != nil {
				return nil, fmt.Errorf("git clone options: %w", err)
			}
			cloneOpts.Path = constants.MagicRemoteRepoDir

			endStage := startStage("📦 Remote repo build mode enabled, cloning %s to %s for build context...",
				newColor(color.FgCyan).Sprintf(opts.GitURL),
				newColor(color.FgCyan).Sprintf(cloneOpts.Path),
			)

			w := git.ProgressWriter(func(line string) { opts.Logger(log.LevelInfo, "#%d: %s", stageNumber, line) })
			defer w.Close()
			cloneOpts.Progress = w

			fallbackErr = git.ShallowCloneRepo(ctx, cloneOpts)
			if fallbackErr == nil {
				endStage("📦 Cloned repository!")
				buildTimeWorkspaceFolder = cloneOpts.Path
			} else {
				opts.Logger(log.LevelError, "Failed to clone repository for remote repo mode: %s", fallbackErr.Error())
				opts.Logger(log.LevelError, "Falling back to the default image...")
			}
		}
	}

	defaultBuildParams := func() (*devcontainer.Compiled, error) {
		dockerfile := filepath.Join(constants.MagicDir, "Dockerfile")
		file, err := opts.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if opts.FallbackImage == "" {
			if fallbackErr != nil {
				return nil, fmt.Errorf("%s: %w", fallbackErr.Error(), constants.ErrNoFallbackImage)
			}
			// We can't use errors.Join here because our tests
			// don't support parsing a multiline error.
			return nil, constants.ErrNoFallbackImage
		}
		content := "FROM " + opts.FallbackImage
		_, err = file.Write([]byte(content))
		if err != nil {
			return nil, err
		}
		return &devcontainer.Compiled{
			DockerfilePath:    dockerfile,
			DockerfileContent: content,
			BuildContext:      constants.MagicDir,
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
				buildParams, err = devContainer.Compile(opts.Filesystem, devcontainerDir, constants.MagicDir, fallbackDockerfile, opts.WorkspaceFolder, false, os.LookupEnv)
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

	HijackLogrus(func(entry *logrus.Entry) {
		for _, line := range strings.Split(entry.Message, "\r") {
			opts.Logger(log.LevelInfo, "#%d: %s", stageNumber, color.HiBlackString(line))
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
		constants.MagicDir,
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
	buildParams.DockerfileContent += constants.MagicDirectives
	envbuilderBinDest := filepath.Join(buildParams.BuildContext, "envbuilder")

	// Copy the envbuilder binary into the build context.
	opts.Logger(log.LevelDebug, "copying envbuilder binary at %q to build context %q", opts.BinaryPath, buildParams.BuildContext)
	if err := copyFile(opts.BinaryPath, envbuilderBinDest, 0o755); err != nil {
		return nil, xerrors.Errorf("copy envbuilder binary to build context: %w", err)
	}

	// Also touch the magic file that signifies the image has been built!
	magicImageDest := filepath.Join(buildParams.BuildContext, filepath.Base(constants.MagicImage))
	if err := touchFile(magicImageDest, 0o755); err != nil {
		return nil, fmt.Errorf("touch magic image file in build context: %w", err)
	}
	defer func() {
		// Clean up after we're done!
		if err := os.Remove(envbuilderBinDest); err != nil {
			opts.Logger(log.LevelWarn, "failed to clean up envbuilder binary from build context: %w", err)
		}
		if err := os.Remove(magicImageDest); err != nil {
			opts.Logger(log.LevelWarn, "failed to clean up magic image file from build context: %w", err)
		}
	}()

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
		CustomPlatform:    platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
		SnapshotMode:      "redo",
		RunV2:             true,
		RunStdout:         stdoutWriter,
		RunStderr:         stderrWriter,
		Destinations:      destinations,
		NoPush:            !opts.PushImage || len(destinations) == 0,
		CacheRunLayers:    true,
		CacheCopyLayers:   true,
		CompressedCaching: true,
		Compression:       config.ZStd,
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
	if err := cleanupDockerConfigJSON(); err != nil {
		return nil, err
	}

	return image, nil
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
	skippedRebuild bool,
	userInfo userInfo,
) error {
	if options.PostStartScriptPath != "" {
		_ = os.Remove(options.PostStartScriptPath)
	}

	if !skippedRebuild {
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
	kanikoDir, ok := os.LookupEnv("KANIKO_DIR")
	if !ok || strings.TrimSpace(kanikoDir) != constants.MagicDir {
		if force {
			bailoutSecs := 10
			logger(log.LevelWarn, "WARNING! BYPASSING SAFETY CHECK! THIS WILL DELETE YOUR ROOT FILESYSTEM!")
			logger(log.LevelWarn, "You have %d seconds to bail out!", bailoutSecs)
			for i := bailoutSecs; i > 0; i-- {
				logger(log.LevelWarn, "%d...", i)
				<-time.After(time.Second)
			}
		} else {
			logger(log.LevelError, "KANIKO_DIR is not set to %s. Bailing!\n", constants.MagicDir)
			logger(log.LevelError, "To bypass this check, set FORCE_SAFE=true.")
			return errors.New("safety check failed")
		}
	}

	return util.DeleteFilesystem()
}

func copyFile(src, dst string, mode fs.FileMode) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read src file failed: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(dst), mode)
	if err != nil {
		return fmt.Errorf("create destination dir failed: %w", err)
	}

	err = os.WriteFile(dst, content, mode)
	if err != nil {
		return fmt.Errorf("write dest file failed: %w", err)
	}
	return nil
}

func touchFile(dst string, mode fs.FileMode) error {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return xerrors.Errorf("failed to touch file: %w", err)
	}
	return f.Close()
}

func initDockerConfigJSON(dockerConfigBase64 string) (func() error, error) {
	var cleanupOnce sync.Once
	noop := func() error { return nil }
	if dockerConfigBase64 == "" {
		return noop, nil
	}
	cfgPath := filepath.Join(constants.MagicDir, "config.json")
	decoded, err := base64.StdEncoding.DecodeString(dockerConfigBase64)
	if err != nil {
		return noop, fmt.Errorf("decode docker config: %w", err)
	}
	var configFile DockerConfig
	decoded, err = hujson.Standardize(decoded)
	if err != nil {
		return noop, fmt.Errorf("humanize json for docker config: %w", err)
	}
	err = json.Unmarshal(decoded, &configFile)
	if err != nil {
		return noop, fmt.Errorf("parse docker config: %w", err)
	}
	err = os.WriteFile(cfgPath, decoded, 0o644)
	if err != nil {
		return noop, fmt.Errorf("write docker config: %w", err)
	}
	cleanup := func() error {
		var cleanupErr error
		cleanupOnce.Do(func() {
			// Remove the Docker config secret file!
			if cleanupErr = os.Remove(cfgPath); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					cleanupErr = fmt.Errorf("remove docker config: %w", cleanupErr)
				}
				_, _ = fmt.Fprintf(os.Stderr, "failed to remove the Docker config secret file: %s\n", cleanupErr)
			}
		})
		return cleanupErr
	}
	return cleanup, err
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
