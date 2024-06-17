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
	"syscall"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/mattn/go-isatty"

	"github.com/GoogleContainerTools/kaniko/pkg/config"
	"github.com/GoogleContainerTools/kaniko/pkg/creds"
	"github.com/GoogleContainerTools/kaniko/pkg/executor"
	"github.com/GoogleContainerTools/kaniko/pkg/util"
	giturls "github.com/chainguard-dev/git-urls"
	"github.com/coder/envbuilder/devcontainer"
	"github.com/coder/envbuilder/internal/ebutil"
	"github.com/coder/envbuilder/internal/notcodersdk"
	"github.com/containerd/containerd/platforms"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry/handlers"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/fatih/color"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing/transport"
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
	MagicDir = "/.envbuilder"
)

var (
	ErrNoFallbackImage = errors.New("no fallback image has been specified")

	// MagicFile is a file that is created in the workspace
	// when envbuilder has already been run. This is used
	// to skip building when a container is restarting.
	// e.g. docker stop -> docker start
	MagicFile = filepath.Join(MagicDir, "built")
)

// DockerConfig represents the Docker configuration file.
type DockerConfig configfile.ConfigFile

// Run runs the envbuilder.
// Logger is the logf to use for all operations.
// Filesystem is the filesystem to use for all operations.
// Defaults to the host filesystem.
func Run(ctx context.Context, options Options) error {
	// Temporarily removed these from the default settings to prevent conflicts
	// between current and legacy environment variables that add default values.
	// Once the legacy environment variables are phased out, this can be
	// reinstated to the previous default values.
	if len(options.IgnorePaths) == 0 {
		options.IgnorePaths = []string{"/var/run"}
	}
	if options.InitScript == "" {
		options.InitScript = "sleep infinity"
	}
	if options.InitCommand == "" {
		options.InitCommand = "/bin/sh"
	}
	if options.CacheRepo == "" && options.PushImage {
		return fmt.Errorf("--cache-repo must be set when using --push-image")
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
		f, err := DefaultWorkspaceFolder(options.GitURL)
		if err != nil {
			return err
		}
		options.WorkspaceFolder = f
	}

	stageNumber := 0
	startStage := func(format string, args ...any) func(format string, args ...any) {
		now := time.Now()
		stageNumber++
		stageNum := stageNumber
		options.Logger(notcodersdk.LogLevelInfo, "#%d: %s", stageNum, fmt.Sprintf(format, args...))

		return func(format string, args ...any) {
			options.Logger(notcodersdk.LogLevelInfo, "#%d: %s [%s]", stageNum, fmt.Sprintf(format, args...), time.Since(now))
		}
	}

	options.Logger(notcodersdk.LogLevelInfo, "%s - Build development environments from repositories in a container", newColor(color.Bold).Sprintf("envbuilder"))

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
		err = os.WriteFile(filepath.Join(MagicDir, "config.json"), decoded, 0o644)
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
					options.Logger(notcodersdk.LogLevelInfo, "#1: %s", strings.TrimSpace(line))
				}
			}
		}()

		cloneOpts := CloneRepoOptions{
			Path:         options.WorkspaceFolder,
			Storage:      options.Filesystem,
			Insecure:     options.Insecure,
			Progress:     writer,
			SingleBranch: options.GitCloneSingleBranch,
			Depth:        int(options.GitCloneDepth),
			CABundle:     caBundle,
		}

		cloneOpts.RepoAuth = SetupRepoAuth(&options)
		if options.GitHTTPProxyURL != "" {
			cloneOpts.ProxyOptions = transport.ProxyOptions{
				URL: options.GitHTTPProxyURL,
			}
		}
		cloneOpts.RepoURL = options.GitURL

		cloned, fallbackErr = CloneRepo(ctx, cloneOpts)
		if fallbackErr == nil {
			if cloned {
				endStage("📦 Cloned repository!")
			} else {
				endStage("📦 The repository already exists!")
			}
		} else {
			options.Logger(notcodersdk.LogLevelError, "Failed to clone repository: %s", fallbackErr.Error())
			options.Logger(notcodersdk.LogLevelError, "Falling back to the default image...")
		}
	}

	defaultBuildParams := func() (*devcontainer.Compiled, error) {
		dockerfile := filepath.Join(MagicDir, "Dockerfile")
		file, err := options.Filesystem.OpenFile(dockerfile, os.O_CREATE|os.O_WRONLY, 0o644)
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

	var (
		buildParams *devcontainer.Compiled
		scripts     devcontainer.LifecycleScripts

		devcontainerPath string
	)
	if options.DockerfilePath == "" {
		// Only look for a devcontainer if a Dockerfile wasn't specified.
		// devcontainer is a standard, so it's reasonable to be the default.
		var devcontainerDir string
		var err error
		devcontainerPath, devcontainerDir, err = findDevcontainerJSON(options)
		if err != nil {
			options.Logger(notcodersdk.LogLevelError, "Failed to locate devcontainer.json: %s", err.Error())
			options.Logger(notcodersdk.LogLevelError, "Falling back to the default image...")
		} else {
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
					options.Logger(notcodersdk.LogLevelInfo, "No Dockerfile or image specified; falling back to the default image...")
					fallbackDockerfile = defaultParams.DockerfilePath
				}
				buildParams, err = devContainer.Compile(options.Filesystem, devcontainerDir, MagicDir, fallbackDockerfile, options.WorkspaceFolder, false, os.LookupEnv)
				if err != nil {
					return fmt.Errorf("compile devcontainer.json: %w", err)
				}
				scripts = devContainer.LifecycleScripts
			} else {
				options.Logger(notcodersdk.LogLevelError, "Failed to parse devcontainer.json: %s", err.Error())
				options.Logger(notcodersdk.LogLevelError, "Falling back to the default image...")
			}
		}
	} else {
		// If a Dockerfile was specified, we use that.
		dockerfilePath := filepath.Join(options.WorkspaceFolder, options.DockerfilePath)

		// If the dockerfilePath is specified and deeper than the base of WorkspaceFolder AND the BuildContextPath is
		// not defined, show a warning
		dockerfileDir := filepath.Dir(dockerfilePath)
		if dockerfileDir != filepath.Clean(options.WorkspaceFolder) && options.BuildContextPath == "" {
			options.Logger(notcodersdk.LogLevelWarn, "given dockerfile %q is below %q and no custom build context has been defined", dockerfilePath, options.WorkspaceFolder)
			options.Logger(notcodersdk.LogLevelWarn, "\t-> set BUILD_CONTEXT_PATH to %q to fix", dockerfileDir)
		}

		dockerfile, err := options.Filesystem.Open(dockerfilePath)
		if err == nil {
			content, err := io.ReadAll(dockerfile)
			if err != nil {
				return fmt.Errorf("read Dockerfile: %w", err)
			}
			buildParams = &devcontainer.Compiled{
				DockerfilePath:    dockerfilePath,
				DockerfileContent: string(content),
				BuildContext:      filepath.Join(options.WorkspaceFolder, options.BuildContextPath),
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
			options.Logger(notcodersdk.LogLevelInfo, "#%d: %s", stageNumber, color.HiBlackString(line))
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
		cfg.Log.Level = "error"

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
				options.Logger(notcodersdk.LogLevelError, "Failed to serve registry: %s", err.Error())
			}
		}()
		closeAfterBuild = func() {
			_ = srv.Close()
			_ = listener.Close()
		}
		if options.CacheRepo != "" {
			options.Logger(notcodersdk.LogLevelWarn, "Overriding cache repo with local registry...")
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
		// See: https://github.com/coder/envbuilder/issues/37
		"/etc/resolv.conf",
	}, options.IgnorePaths...)

	for _, ignorePath := range ignorePaths {
		util.AddToDefaultIgnoreList(util.IgnoreListEntry{
			Path:            ignorePath,
			PrefixMatchOnly: false,
		})
	}

	// temp move of all ro mounts
	tempRemountDest := filepath.Join("/", MagicDir, "mnt")
	ignorePrefixes := []string{tempRemountDest, "/proc", "/sys"}
	restoreMounts, err := ebutil.TempRemount(options.Logger, tempRemountDest, ignorePrefixes...)
	defer func() { // restoreMounts should never be nil
		if err := restoreMounts(); err != nil {
			options.Logger(notcodersdk.LogLevelError, "restore mounts: %s", err.Error())
		}
	}()
	if err != nil {
		return fmt.Errorf("temp remount: %w", err)
	}

	skippedRebuild := false
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
		if err := maybeDeleteFilesystem(options.Logger, options.ForceSafe); err != nil {
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
				options.Logger(notcodersdk.LogLevelInfo, "%s", scanner.Text())
			}
		}()
		go func() {
			scanner := bufio.NewScanner(stderrReader)
			for scanner.Scan() {
				options.Logger(notcodersdk.LogLevelInfo, "%s", scanner.Text())
			}
		}()
		cacheTTL := time.Hour * 24 * 7
		if options.CacheTTLDays != 0 {
			cacheTTL = time.Hour * 24 * time.Duration(options.CacheTTLDays)
		}

		// At this point we have all the context, we can now build!
		registryMirror := []string{}
		if val, ok := os.LookupEnv("KANIKO_REGISTRY_MIRROR"); ok {
			registryMirror = strings.Split(val, ";")
		}
		var destinations []string
		if options.CacheRepo != "" {
			destinations = append(destinations, options.CacheRepo)
		}
		opts := &config.KanikoOptions{
			// Boilerplate!
			CustomPlatform:    platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
			SnapshotMode:      "redo",
			RunV2:             true,
			RunStdout:         stdoutWriter,
			RunStderr:         stderrWriter,
			Destinations:      destinations,
			NoPush:            !options.PushImage || len(destinations) == 0,
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
				CacheTTL: cacheTTL,
				CacheDir: options.BaseImageCacheDir,
			},
			ForceUnpack:       true,
			BuildArgs:         buildParams.BuildArgs,
			CacheRepo:         options.CacheRepo,
			Cache:             options.CacheRepo != "" || options.BaseImageCacheDir != "",
			DockerfilePath:    buildParams.DockerfilePath,
			DockerfileContent: buildParams.DockerfileContent,
			RegistryOptions: config.RegistryOptions{
				Insecure:      options.Insecure,
				InsecurePull:  options.Insecure,
				SkipTLSVerify: options.Insecure,
				// Enables registry mirror features in Kaniko, see more in link below
				// https://github.com/GoogleContainerTools/kaniko?tab=readme-ov-file#flag---registry-mirror
				// Related to PR #114
				// https://github.com/coder/envbuilder/pull/114
				RegistryMirrors: registryMirror,
			},
			SrcContext: buildParams.BuildContext,

			// For cached image utilization, produce reproducible builds.
			Reproducible: options.PushImage,
		}

		if options.GetCachedImage {
			endStage := startStage("🏗️ Checking for cached image...")
			image, err := executor.DoCacheProbe(opts)
			if err != nil {
				return nil, xerrors.Errorf("get cached image: %w", err)
			}
			digest, err := image.Digest()
			if err != nil {
				return nil, xerrors.Errorf("get cached image digest: %w", err)
			}
			endStage("🏗️ Found cached image!")
			_, _ = fmt.Fprintf(os.Stdout, "%s@%s\n", options.CacheRepo, digest.String())
			os.Exit(0)
		}

		endStage := startStage("🏗️ Building image...")
		image, err := executor.DoBuild(opts)
		if err != nil {
			return nil, xerrors.Errorf("do build: %w", err)
		}
		endStage("🏗️ Built image!")
		if options.PushImage {
			endStage = startStage("🏗️ Pushing image...")
			if err := executor.DoPush(image, opts); err != nil {
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
			options.Logger(notcodersdk.LogLevelError, "Unable to pull the provided image. Ensure your registry credentials are correct!")
		}
		if !fallback || options.ExitOnBuildFailure {
			return err
		}
		options.Logger(notcodersdk.LogLevelError, "Failed to build: %s", err)
		options.Logger(notcodersdk.LogLevelError, "Falling back to the default image...")
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

	if err := restoreMounts(); err != nil {
		return fmt.Errorf("restore mounts: %w", err)
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
		options.Logger(notcodersdk.LogLevelInfo, "#3: 👀 Found devcontainer.json label metadata in image...")
		for _, container := range devContainer {
			if container.RemoteUser != "" {
				options.Logger(notcodersdk.LogLevelInfo, "#3: 🧑 Updating the user to %q!", container.RemoteUser)

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

	// Sanitize the environment of any options!
	unsetOptionsEnv()

	// Remove the Docker config secret file!
	if options.DockerConfigBase64 != "" {
		c := filepath.Join(MagicDir, "config.json")
		err = os.Remove(c)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("remove docker config: %w", err)
			} else {
				fmt.Fprintln(os.Stderr, "failed to remove the Docker config secret file: %w", c)
			}
		}
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
			value := devcontainer.SubstituteVars(env[envVar], options.WorkspaceFolder, os.LookupEnv)
			os.Setenv(envVar, value)
		}
	}

	// Do not export env if we skipped a rebuild, because ENV directives
	// from the Dockerfile would not have been processed and we'd miss these
	// in the export. We should have generated a complete set of environment
	// on the intial build, so exporting environment variables a second time
	// isn't useful anyway.
	if options.ExportEnvFile != "" && !skippedRebuild {
		exportEnvFile, err := os.Create(options.ExportEnvFile)
		if err != nil {
			return fmt.Errorf("failed to open EXPORT_ENV_FILE %q: %w", options.ExportEnvFile, err)
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
		options.Logger(notcodersdk.LogLevelWarn, "#3: no user specified, using root")
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
		if chownErr := filepath.Walk(options.WorkspaceFolder, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Chown(path, userInfo.uid, userInfo.gid)
		}); chownErr != nil {
			options.Logger(notcodersdk.LogLevelError, "chown %q: %s", userInfo.user.HomeDir, chownErr.Error())
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
			options.Logger(notcodersdk.LogLevelError, "chown %q: %s", userInfo.user.HomeDir, chownErr.Error())
			endStage("⚠️ Failed to update ownership of %s, you may need to fix this manually!", userInfo.user.HomeDir)
		} else {
			endStage("🏡 Updated ownership of %s!", userInfo.user.HomeDir)
		}
	}

	err = os.MkdirAll(options.WorkspaceFolder, 0o755)
	if err != nil {
		return fmt.Errorf("create workspace folder: %w", err)
	}
	err = os.Chdir(options.WorkspaceFolder)
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
	if err := execLifecycleScripts(ctx, options, scripts, skippedRebuild, userInfo); err != nil {
		return err
	}

	// The setup script can specify a custom initialization command
	// and arguments to run instead of the default shell.
	//
	// This is useful for hooking into the environment for a specific
	// init to PID 1.
	if options.SetupScript != "" {
		// We execute the initialize script as the root user!
		os.Setenv("HOME", "/root")

		options.Logger(notcodersdk.LogLevelInfo, "=== Running the setup command %q as the root user...", options.SetupScript)

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
			fmt.Sprintf("TARGET_USER=%s", userInfo.user.Username),
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
					options.Logger(notcodersdk.LogLevelInfo, "%s", scanner.Text())
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

	options.Logger(notcodersdk.LogLevelInfo, "=== Running the init command %s %+v as the %q user...", options.InitCommand, initArgs, userInfo.user.Username)

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
		return EmptyWorkspaceDir, nil
	}
	parsed, err := giturls.Parse(repoURL)
	if err != nil {
		return "", err
	}
	name := strings.Split(parsed.Path, "/")
	hasOwnerAndRepo := len(name) >= 2
	if !hasOwnerAndRepo {
		return EmptyWorkspaceDir, nil
	}
	repo := strings.TrimSuffix(name[len(name)-1], ".git")
	return fmt.Sprintf("/workspaces/%s", repo), nil
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
	logf func(level notcodersdk.LogLevel, format string, args ...any),
	s devcontainer.LifecycleScript,
	scriptName string,
	userInfo userInfo,
) error {
	if s.IsEmpty() {
		return nil
	}
	logf(notcodersdk.LogLevelInfo, "=== Running %s as the %q user...", scriptName, userInfo.user.Username)
	if err := s.Execute(ctx, userInfo.uid, userInfo.gid); err != nil {
		logf(notcodersdk.LogLevelError, "Failed to run %s: %v", scriptName, err)
		return err
	}
	return nil
}

func execLifecycleScripts(
	ctx context.Context,
	options Options,
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

// unsetOptionsEnv unsets all environment variables that are used
// to configure the options.
func unsetOptionsEnv() {
	var o Options
	for _, opt := range o.CLI() {
		if opt.Env == "" {
			continue
		}
		os.Unsetenv(opt.Env)
		os.Unsetenv(strings.TrimPrefix(opt.Env, envPrefix))
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

func findDevcontainerJSON(options Options) (string, string, error) {
	// 0. Check if custom devcontainer directory or path is provided.
	if options.DevcontainerDir != "" || options.DevcontainerJSONPath != "" {
		devcontainerDir := options.DevcontainerDir
		if devcontainerDir == "" {
			devcontainerDir = ".devcontainer"
		}

		// If `devcontainerDir` is not an absolute path, assume it is relative to the workspace folder.
		if !filepath.IsAbs(devcontainerDir) {
			devcontainerDir = filepath.Join(options.WorkspaceFolder, devcontainerDir)
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

	// 1. Check `options.WorkspaceFolder`/.devcontainer/devcontainer.json.
	location := filepath.Join(options.WorkspaceFolder, ".devcontainer", "devcontainer.json")
	if _, err := options.Filesystem.Stat(location); err == nil {
		return location, filepath.Dir(location), nil
	}

	// 2. Check `options.WorkspaceFolder`/devcontainer.json.
	location = filepath.Join(options.WorkspaceFolder, "devcontainer.json")
	if _, err := options.Filesystem.Stat(location); err == nil {
		return location, filepath.Dir(location), nil
	}

	// 3. Check every folder: `options.WorkspaceFolder`/.devcontainer/<folder>/devcontainer.json.
	devcontainerDir := filepath.Join(options.WorkspaceFolder, ".devcontainer")

	fileInfos, err := options.Filesystem.ReadDir(devcontainerDir)
	if err != nil {
		return "", "", err
	}

	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() {
			options.Logger(notcodersdk.LogLevelDebug, `%s is a file`, fileInfo.Name())
			continue
		}

		location := filepath.Join(devcontainerDir, fileInfo.Name(), "devcontainer.json")
		if _, err := options.Filesystem.Stat(location); err != nil {
			options.Logger(notcodersdk.LogLevelDebug, `stat %s failed: %s`, location, err.Error())
			continue
		}

		return location, filepath.Dir(location), nil
	}

	return "", "", errors.New("can't find devcontainer.json, is it a correct spec?")
}

// maybeDeleteFilesystem wraps util.DeleteFilesystem with a guard to hopefully stop
// folks from unwittingly deleting their entire root directory.
func maybeDeleteFilesystem(log LoggerFunc, force bool) error {
	kanikoDir, ok := os.LookupEnv("KANIKO_DIR")
	if !ok || strings.TrimSpace(kanikoDir) != MagicDir {
		if force {
			bailoutSecs := 10
			log(notcodersdk.LogLevelWarn, "WARNING! BYPASSING SAFETY CHECK! THIS WILL DELETE YOUR ROOT FILESYSTEM!")
			log(notcodersdk.LogLevelWarn, "You have %d seconds to bail out!", bailoutSecs)
			for i := bailoutSecs; i > 0; i-- {
				log(notcodersdk.LogLevelWarn, "%d...", i)
				<-time.After(time.Second)
			}
		} else {
			log(notcodersdk.LogLevelError, "KANIKO_DIR is not set to %s. Bailing!\n", MagicDir)
			log(notcodersdk.LogLevelError, "To bypass this check, set FORCE_SAFE=true.")
			return errors.New("safety check failed")
		}
	}

	return util.DeleteFilesystem()
}
