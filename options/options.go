package options

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/coder/envbuilder/log"
	"github.com/coder/serpent"
	"github.com/go-git/go-billy/v5"
)

// Options contains the configuration for the envbuilder.
type Options struct {
	// SetupScript is the script to run before the init script. It runs as the
	// root user regardless of the user specified in the devcontainer.json file.
	// SetupScript is ran as the root user prior to the init script. It is used to
	// configure envbuilder dynamically during the runtime. e.g. specifying
	// whether to start systemd or tiny init for PID 1.
	SetupScript string
	// InitScript is the script to run to initialize the workspace.
	InitScript string
	// InitCommand is the command to run to initialize the workspace.
	InitCommand string
	// InitArgs are the arguments to pass to the init command. They are split
	// according to /bin/sh rules with https://github.com/kballard/go-shellquote.
	InitArgs string
	// CacheRepo is the name of the container registry to push the cache image to.
	// If this is empty, the cache will not be pushed.
	CacheRepo string
	// BaseImageCacheDir is the path to a directory where the base image can be
	// found. This should be a read-only directory solely mounted for the purpose
	// of caching the base image.
	BaseImageCacheDir string
	// LayerCacheDir is the path to a directory where built layers will be stored.
	// This spawns an in-memory registry to serve the layers from.
	LayerCacheDir string
	// DevcontainerDir is the path to the folder containing the devcontainer.json
	// file that will be used to build the workspace and can either be an absolute
	// path or a path relative to the workspace folder. If not provided, defaults
	// to `.devcontainer`.
	DevcontainerDir string
	// DevcontainerJSONPath is a path to a devcontainer.json file
	// that is either an absolute path or a path relative to
	// DevcontainerDir. This can be used in cases where one wants
	// to substitute an edited devcontainer.json file for the one
	// that exists in the repo.
	// If neither `DevcontainerDir` nor `DevcontainerJSONPath` is provided,
	// envbuilder will browse following directories to locate it:
	// 1. `.devcontainer/devcontainer.json`
	// 2. `.devcontainer.json`
	// 3. `.devcontainer/<folder>/devcontainer.json`
	DevcontainerJSONPath string
	// DockerfilePath is the relative path to the Dockerfile that will be used to
	// build the workspace. This is an alternative to using a devcontainer that
	// some might find simpler.
	DockerfilePath string
	// BuildContextPath can be specified when a DockerfilePath is specified
	// outside the base WorkspaceFolder. This path MUST be relative to the
	// WorkspaceFolder path into which the repo is cloned.
	BuildContextPath string
	// CacheTTLDays is the number of days to use cached layers before expiring
	// them. Defaults to 7 days.
	CacheTTLDays int64
	// DockerConfigBase64 is the base64 encoded Docker config file that will be
	// used to pull images from private container registries.
	DockerConfigBase64 string
	// FallbackImage specifies an alternative image to use when neither an image
	// is declared in the devcontainer.json file nor a Dockerfile is present. If
	// there's a build failure (from a faulty Dockerfile) or a misconfiguration,
	// this image will be the substitute. Set ExitOnBuildFailure to true to halt
	// the container if the build faces an issue.
	FallbackImage string
	// ExitOnBuildFailure terminates the container upon a build failure. This is
	// handy when preferring the FALLBACK_IMAGE in cases where no
	// devcontainer.json or image is provided. However, it ensures that the
	// container stops if the build process encounters an error.
	ExitOnBuildFailure bool
	// ExitOnPushFailure terminates the container upon a push failure. This is
	// useful if failure to push the built image should abort execution
	// and result in an error.
	ExitOnPushFailure bool
	// ForceSafe ignores any filesystem safety checks. This could cause serious
	// harm to your system! This is used in cases where bypass is needed to
	// unblock customers.
	ForceSafe bool
	// Insecure bypasses TLS verification when cloning and pulling from container
	// registries.
	Insecure bool
	// IgnorePaths is the comma separated list of paths to ignore when building
	// the workspace.
	IgnorePaths []string
	// BuildSecrets is the list of secret environment variables to use when
	// building the image.
	BuildSecrets []string
	// SkipRebuild skips building if the MagicFile exists. This is used to skip
	// building when a container is restarting. e.g. docker stop -> docker start
	// This value can always be set to true - even if the container is being
	// started for the first time.
	SkipRebuild bool
	// SkipUnusedStages builds only used stages if defined to true. Otherwise,
	// it builds by default all stages, even the unnecessary ones until it
	// reaches the target stage / end of Dockerfile
	SkipUnusedStages bool
	// GitURL is the URL of the Git repository to clone. This is optional.
	GitURL string
	// GitCloneDepth is the depth to use when cloning the Git repository.
	GitCloneDepth int64
	// GitCloneSingleBranch clone only a single branch of the Git repository.
	GitCloneSingleBranch bool
	// GitUsername is the username to use for Git authentication. This is
	// optional.
	GitUsername string
	// GitPassword is the password to use for Git authentication. This is
	// optional.
	GitPassword string
	// GitSSHPrivateKeyPath is the path to an SSH private key to be used for
	// Git authentication.
	GitSSHPrivateKeyPath string
	// GitSSHPrivateKeyBase64 is the content of an SSH private key to be used
	// for Git authentication.
	GitSSHPrivateKeyBase64 string
	// GitHTTPProxyURL is the URL for the HTTP proxy. This is optional.
	GitHTTPProxyURL string
	// WorkspaceBaseDir is the path under which workspaces will be placed when
	// workspace folder option is not given.
	WorkspaceBaseDir string
	// WorkspaceFolder is the path to the workspace folder that will be built.
	// This is optional. Defaults to `[workspace base dir]/[name]` where name is
	// the name of the repository or "empty".
	WorkspaceFolder string
	// SSLCertBase64 is the content of an SSL cert file. This is useful for
	// self-signed certificates.
	SSLCertBase64 string
	// ExportEnvFile is the optional file path to a .env file where envbuilder
	// will dump environment variables from devcontainer.json and the built
	// container image.
	ExportEnvFile string
	// PostStartScriptPath is the path to a script that will be created by
	// envbuilder based on the postStartCommand in devcontainer.json, if any is
	// specified (otherwise the script is not created). If this is set, the
	// specified InitCommand should check for the presence of this script and
	// execute it after successful startup.
	PostStartScriptPath string
	// Logger is the logger to use for all operations.
	Logger log.Func
	// Verbose controls whether to send verbose logs.
	Verbose bool
	// Filesystem is the filesystem to use for all operations. Defaults to the
	// host filesystem.
	Filesystem billy.Filesystem
	// These options are specifically used when envbuilder is invoked as part of a
	// Coder workspace.
	// Revert to `*url.URL` once https://github.com/coder/serpent/issues/14 is fixed.
	CoderAgentURL string
	// CoderAgentToken is the authentication token for a Coder agent.
	CoderAgentToken string
	// CoderAgentSubsystem is the Coder agent subsystems to report when forwarding
	// logs. The envbuilder subsystem is always included.
	CoderAgentSubsystem []string

	// PushImage is a flag to determine if the image should be pushed to the
	// container registry. This option implies reproducible builds.
	PushImage bool
	// GetCachedImage is a flag to determine if the cached image is available,
	// and if it is, to return it.
	GetCachedImage bool

	// RemoteRepoBuildMode uses the remote repository as the source of truth
	// when building the image. Enabling this option ignores user changes to
	// local files and they will not be reflected in the image. This can be
	// used to improving cache utilization when multiple users are building
	// working on the same repository.
	RemoteRepoBuildMode bool

	// BinaryPath is the path to the local envbuilder binary when
	// attempting to probe the build cache. This is only relevant when
	// GetCachedImage is true.
	BinaryPath string

	// WorkingDirBase is the path to the directory where all envbuilder files should be
	// stored. By default, this is set to `/.envbuilder`. This is intentionally
	// excluded from the CLI options.
	WorkingDirBase string
}

const envPrefix = "ENVBUILDER_"

// Generate CLI options for the envbuilder command.
func (o *Options) CLI() serpent.OptionSet {
	options := serpent.OptionSet{
		{
			Flag:  "setup-script",
			Env:   WithEnvPrefix("SETUP_SCRIPT"),
			Value: serpent.StringOf(&o.SetupScript),
			Description: "The script to run before the init script. It runs as " +
				"the root user regardless of the user specified in the devcontainer.json " +
				"file. SetupScript is ran as the root user prior to the init script. " +
				"It is used to configure envbuilder dynamically during the runtime. e.g. " +
				"specifying whether to start systemd or tiny init for PID 1.",
		},
		{
			Flag: "init-script",
			Env:  WithEnvPrefix("INIT_SCRIPT"),
			// Default:     "sleep infinity", // TODO: reinstate once legacy opts are removed.
			Value:       serpent.StringOf(&o.InitScript),
			Description: "The script to run to initialize the workspace. Default: `sleep infinity`.",
		},
		{
			Flag: "init-command",
			Env:  WithEnvPrefix("INIT_COMMAND"),
			// Default:     "/bin/sh", // TODO: reinstate once legacy opts are removed.
			Value:       serpent.StringOf(&o.InitCommand),
			Description: "The command to run to initialize the workspace. Default: `/bin/sh`.",
		},
		{
			Flag:  "init-args",
			Env:   WithEnvPrefix("INIT_ARGS"),
			Value: serpent.StringOf(&o.InitArgs),
			Description: "The arguments to pass to the init command. They are " +
				"split according to /bin/sh rules with " +
				"https://github.com/kballard/go-shellquote.",
		},
		{
			Flag:  "cache-repo",
			Env:   WithEnvPrefix("CACHE_REPO"),
			Value: serpent.StringOf(&o.CacheRepo),
			Description: "The name of the container registry to push the cache " +
				"image to. If this is empty, the cache will not be pushed.",
		},
		{
			Flag:  "base-image-cache-dir",
			Env:   WithEnvPrefix("BASE_IMAGE_CACHE_DIR"),
			Value: serpent.StringOf(&o.BaseImageCacheDir),
			Description: "The path to a directory where the base image " +
				"can be found. This should be a read-only directory solely mounted " +
				"for the purpose of caching the base image.",
		},
		{
			Flag:  "layer-cache-dir",
			Env:   WithEnvPrefix("LAYER_CACHE_DIR"),
			Value: serpent.StringOf(&o.LayerCacheDir),
			Description: "The path to a directory where built layers will " +
				"be stored. This spawns an in-memory registry to serve the layers " +
				"from.",
		},
		{
			Flag:  "devcontainer-dir",
			Env:   WithEnvPrefix("DEVCONTAINER_DIR"),
			Value: serpent.StringOf(&o.DevcontainerDir),
			Description: "The path to the folder containing the " +
				"devcontainer.json file that will be used to build the workspace " +
				"and can either be an absolute path or a path relative to the " +
				"workspace folder. If not provided, defaults to `.devcontainer`.",
		},
		{
			Flag:  "devcontainer-json-path",
			Env:   WithEnvPrefix("DEVCONTAINER_JSON_PATH"),
			Value: serpent.StringOf(&o.DevcontainerJSONPath),
			Description: "The path to a devcontainer.json file that " +
				"is either an absolute path or a path relative to DevcontainerDir. " +
				"This can be used in cases where one wants to substitute an edited " +
				"devcontainer.json file for the one that exists in the repo.",
		},
		{
			Flag:  "dockerfile-path",
			Env:   WithEnvPrefix("DOCKERFILE_PATH"),
			Value: serpent.StringOf(&o.DockerfilePath),
			Description: "The relative path to the Dockerfile that will " +
				"be used to build the workspace. This is an alternative to using " +
				"a devcontainer that some might find simpler.",
		},
		{
			Flag:  "build-context-path",
			Env:   WithEnvPrefix("BUILD_CONTEXT_PATH"),
			Value: serpent.StringOf(&o.BuildContextPath),
			Description: "Can be specified when a DockerfilePath is " +
				"specified outside the base WorkspaceFolder. This path MUST be " +
				"relative to the WorkspaceFolder path into which the repo is cloned.",
		},
		{
			Flag:  "cache-ttl-days",
			Env:   WithEnvPrefix("CACHE_TTL_DAYS"),
			Value: serpent.Int64Of(&o.CacheTTLDays),
			Description: "The number of days to use cached layers before " +
				"expiring them. Defaults to 7 days.",
		},
		{
			Flag:  "docker-config-base64",
			Env:   WithEnvPrefix("DOCKER_CONFIG_BASE64"),
			Value: serpent.StringOf(&o.DockerConfigBase64),
			Description: "The base64 encoded Docker config file that " +
				"will be used to pull images from private container registries. " +
				"When this is set, Docker configuration set via the DOCKER_CONFIG " +
				"environment variable is ignored.",
		},
		{
			Flag:  "fallback-image",
			Env:   WithEnvPrefix("FALLBACK_IMAGE"),
			Value: serpent.StringOf(&o.FallbackImage),
			Description: "Specifies an alternative image to use when neither " +
				"an image is declared in the devcontainer.json file nor a Dockerfile " +
				"is present. If there's a build failure (from a faulty Dockerfile) " +
				"or a misconfiguration, this image will be the substitute. Set " +
				"ExitOnBuildFailure to true to halt the container if the build " +
				"faces an issue.",
		},
		{
			Flag:  "exit-on-build-failure",
			Env:   WithEnvPrefix("EXIT_ON_BUILD_FAILURE"),
			Value: serpent.BoolOf(&o.ExitOnBuildFailure),
			Description: "Terminates the container upon a build failure. " +
				"This is handy when preferring the FALLBACK_IMAGE in cases where " +
				"no devcontainer.json or image is provided. However, it ensures " +
				"that the container stops if the build process encounters an error.",
		},
		{
			Flag:  "exit-on-push-failure",
			Env:   WithEnvPrefix("EXIT_ON_PUSH_FAILURE"),
			Value: serpent.BoolOf(&o.ExitOnPushFailure),
			Description: "ExitOnPushFailure terminates the container upon a push failure. " +
				"This is useful if failure to push the built image should abort execution " +
				"and result in an error.",
		},
		{
			Flag:  "force-safe",
			Env:   WithEnvPrefix("FORCE_SAFE"),
			Value: serpent.BoolOf(&o.ForceSafe),
			Description: "Ignores any filesystem safety checks. This could cause " +
				"serious harm to your system! This is used in cases where bypass " +
				"is needed to unblock customers.",
		},
		{
			Flag:  "insecure",
			Env:   WithEnvPrefix("INSECURE"),
			Value: serpent.BoolOf(&o.Insecure),
			Description: "Bypass TLS verification when cloning and pulling from " +
				"container registries.",
		},
		{
			Flag:  "ignore-paths",
			Env:   WithEnvPrefix("IGNORE_PATHS"),
			Value: serpent.StringArrayOf(&o.IgnorePaths),
			Description: "The comma separated list of paths to ignore when " +
				"building the workspace.",
		},
		{
			Flag:        "build-secrets",
			Env:         WithEnvPrefix("BUILD_SECRETS"),
			Value:       serpent.StringArrayOf(&o.BuildSecrets),
			Description: "The list of secret environment variables to use " + "when building the image.",
		},
		{
			Flag:  "skip-rebuild",
			Env:   WithEnvPrefix("SKIP_REBUILD"),
			Value: serpent.BoolOf(&o.SkipRebuild),
			Description: "Skip building if the MagicFile exists. This is used " +
				"to skip building when a container is restarting. e.g. docker stop -> " +
				"docker start This value can always be set to true - even if the " +
				"container is being started for the first time.",
		},
		{
			Flag:  "skip-unused-stages",
			Env:   WithEnvPrefix("SKIP_UNUSED_STAGES"),
			Value: serpent.BoolOf(&o.SkipUnusedStages),
			Description: "Skip building all unused docker stages. Otherwise it builds by " +
				"default all stages, even the unnecessary ones until it reaches the " +
				"target stage / end of Dockerfile.",
		},
		{
			Flag:        "git-url",
			Env:         WithEnvPrefix("GIT_URL"),
			Value:       serpent.StringOf(&o.GitURL),
			Description: "The URL of a Git repository containing a Devcontainer or Docker image to clone. This is optional.",
		},
		{
			Flag:        "git-clone-depth",
			Env:         WithEnvPrefix("GIT_CLONE_DEPTH"),
			Value:       serpent.Int64Of(&o.GitCloneDepth),
			Description: "The depth to use when cloning the Git repository.",
		},
		{
			Flag:        "git-clone-single-branch",
			Env:         WithEnvPrefix("GIT_CLONE_SINGLE_BRANCH"),
			Value:       serpent.BoolOf(&o.GitCloneSingleBranch),
			Description: "Clone only a single branch of the Git repository.",
		},
		{
			Flag:        "git-username",
			Env:         WithEnvPrefix("GIT_USERNAME"),
			Value:       serpent.StringOf(&o.GitUsername),
			Description: "The username to use for Git authentication. This is optional.",
		},
		{
			Flag:        "git-password",
			Env:         WithEnvPrefix("GIT_PASSWORD"),
			Value:       serpent.StringOf(&o.GitPassword),
			Description: "The password to use for Git authentication. This is optional.",
		},
		{
			Flag:  "git-ssh-private-key-path",
			Env:   WithEnvPrefix("GIT_SSH_PRIVATE_KEY_PATH"),
			Value: serpent.StringOf(&o.GitSSHPrivateKeyPath),
			Description: "Path to an SSH private key to be used for Git authentication." +
				" If this is set, then GIT_SSH_PRIVATE_KEY_BASE64 cannot be set.",
		},
		{
			Flag:  "git-ssh-private-key-base64",
			Env:   WithEnvPrefix("GIT_SSH_PRIVATE_KEY_BASE64"),
			Value: serpent.StringOf(&o.GitSSHPrivateKeyBase64),
			Description: "Base64 encoded SSH private key to be used for Git authentication." +
				" If this is set, then GIT_SSH_PRIVATE_KEY_PATH cannot be set.",
		},
		{
			Flag:        "git-http-proxy-url",
			Env:         WithEnvPrefix("GIT_HTTP_PROXY_URL"),
			Value:       serpent.StringOf(&o.GitHTTPProxyURL),
			Description: "The URL for the HTTP proxy. This is optional.",
		},
		{
			Flag:    "workspace-base-dir",
			Env:     WithEnvPrefix("WORKSPACE_BASE_DIR"),
			Value:   serpent.StringOf(&o.WorkspaceBaseDir),
			Default: "/workspaces",
			Description: "The path under which workspaces will be placed when " +
				"workspace folder option is not given.",
		},
		{
			Flag:  "workspace-folder",
			Env:   WithEnvPrefix("WORKSPACE_FOLDER"),
			Value: serpent.StringOf(&o.WorkspaceFolder),
			Description: "The path to the workspace folder that will be built. " +
				"This is optional. Defaults to `[workspace base dir]/[name]` where " +
				"name is the name of the repository or `empty`.",
		},
		{
			Flag:  "ssl-cert-base64",
			Env:   WithEnvPrefix("SSL_CERT_BASE64"),
			Value: serpent.StringOf(&o.SSLCertBase64),
			Description: "The content of an SSL cert file. This is useful " +
				"for self-signed certificates.",
		},
		{
			Flag:  "export-env-file",
			Env:   WithEnvPrefix("EXPORT_ENV_FILE"),
			Value: serpent.StringOf(&o.ExportEnvFile),
			Description: "Optional file path to a .env file where " +
				"envbuilder will dump environment variables from devcontainer.json " +
				"and the built container image.",
		},
		{
			Flag:  "post-start-script-path",
			Env:   WithEnvPrefix("POST_START_SCRIPT_PATH"),
			Value: serpent.StringOf(&o.PostStartScriptPath),
			Description: "The path to a script that will be created " +
				"by envbuilder based on the postStartCommand in devcontainer.json, " +
				"if any is specified (otherwise the script is not created). If this " +
				"is set, the specified InitCommand should check for the presence of " +
				"this script and execute it after successful startup.",
		},
		{
			Flag:  "coder-agent-url",
			Env:   "CODER_AGENT_URL",
			Value: serpent.StringOf(&o.CoderAgentURL),
			Description: "URL of the Coder deployment. If CODER_AGENT_TOKEN is also " +
				"set, logs from envbuilder will be forwarded here and will be " +
				"visible in the workspace build logs.",
		},
		{
			Flag:  "coder-agent-token",
			Env:   "CODER_AGENT_TOKEN",
			Value: serpent.StringOf(&o.CoderAgentToken),
			Description: "Authentication token for a Coder agent. If this is set, " +
				"then CODER_AGENT_URL must also be set.",
		},
		{
			Flag:  "coder-agent-subsystem",
			Env:   "CODER_AGENT_SUBSYSTEM",
			Value: serpent.StringArrayOf(&o.CoderAgentSubsystem),
			Description: "Coder agent subsystems to report when forwarding logs. " +
				"The envbuilder subsystem is always included.",
		},
		{
			Flag:  "push-image",
			Env:   WithEnvPrefix("PUSH_IMAGE"),
			Value: serpent.BoolOf(&o.PushImage),
			Description: "Push the built image to a remote registry. " +
				"This option forces a reproducible build.",
		},
		{
			Flag:  "get-cached-image",
			Env:   WithEnvPrefix("GET_CACHED_IMAGE"),
			Value: serpent.BoolOf(&o.GetCachedImage),
			Description: "Print the digest of the cached image, if available. " +
				"Exits with an error if not found.",
		},
		{
			Flag:        "binary-path",
			Env:         WithEnvPrefix("BINARY_PATH"),
			Value:       serpent.StringOf(&o.BinaryPath),
			Hidden:      true,
			Description: "Specify the path to an Envbuilder binary for use when probing the build cache.",
		},
		{
			Flag:    "remote-repo-build-mode",
			Env:     WithEnvPrefix("REMOTE_REPO_BUILD_MODE"),
			Value:   serpent.BoolOf(&o.RemoteRepoBuildMode),
			Default: "false",
			Description: "Use the remote repository as the source of truth " +
				"when building the image. Enabling this option ignores user changes " +
				"to local files and they will not be reflected in the image. This can " +
				"be used to improving cache utilization when multiple users are building " +
				"working on the same repository.",
		},
		{
			Flag:        "verbose",
			Env:         WithEnvPrefix("VERBOSE"),
			Value:       serpent.BoolOf(&o.Verbose),
			Description: "Enable verbose logging.",
		},
	}

	// Add options without the prefix for backward compatibility. These options
	// are marked as deprecated and will be removed in future versions. Note:
	// Future versions will require the 'ENVBUILDER_' prefix for default
	// environment variables.
	options = supportLegacyEnvWithoutPrefixes(options)

	return options
}

func WithEnvPrefix(str string) string {
	return envPrefix + str
}

func supportLegacyEnvWithoutPrefixes(opts serpent.OptionSet) serpent.OptionSet {
	withLegacyOpts := opts

	for _, o := range opts {
		if strings.HasPrefix(o.Env, envPrefix) {
			prevOption := o
			prevOption.Flag = "legacy-" + o.Flag
			prevOption.Env = strings.TrimPrefix(o.Env, envPrefix)
			prevOption.UseInstead = []serpent.Option{o}
			prevOption.Hidden = true
			prevOption.Default = ""
			withLegacyOpts = append(withLegacyOpts, prevOption)
		}
	}

	return withLegacyOpts
}

func (o *Options) Markdown() string {
	cliOptions := skipDeprecatedOptions(o.CLI())

	var sb strings.Builder
	_, _ = sb.WriteString("| Flag | Environment variable | Default | Description |\n")
	_, _ = sb.WriteString("| - | - | - | - |\n")

	for _, opt := range cliOptions {
		if opt.Hidden {
			continue
		}
		d := opt.Default
		if d != "" {
			d = "`" + d + "`"
		}
		_, _ = sb.WriteString("| `--")
		_, _ = sb.WriteString(opt.Flag)
		_, _ = sb.WriteString("` | `")
		_, _ = sb.WriteString(opt.Env)
		_, _ = sb.WriteString("` | ")
		_, _ = sb.WriteString(d)
		_, _ = sb.WriteString(" | ")
		_, _ = sb.WriteString(opt.Description)
		_, _ = sb.WriteString(" |\n")
	}

	return sb.String()
}

func (o *Options) CABundle() ([]byte, error) {
	if o.SSLCertBase64 == "" {
		return nil, nil
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("get global system cert pool: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(o.SSLCertBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode ssl cert: %w", err)
	}
	ok := certPool.AppendCertsFromPEM(data)
	if !ok {
		return nil, fmt.Errorf("failed to append the ssl cert to the global pool: %s", data)
	}
	return data, nil
}

func skipDeprecatedOptions(options []serpent.Option) []serpent.Option {
	var activeOptions []serpent.Option

	for _, opt := range options {
		isDeprecated := len(opt.UseInstead) > 0
		if !isDeprecated {
			activeOptions = append(activeOptions, opt)
		}
	}

	return activeOptions
}

// UnsetEnv unsets all environment variables that are used
// to configure the options.
func UnsetEnv() {
	var o Options
	for _, opt := range o.CLI() {
		if opt.Env == "" {
			continue
		}
		// Do not strip options that do not have the magic prefix!
		// For example, CODER_AGENT_URL, CODER_AGENT_TOKEN, CODER_AGENT_SUBSYSTEM.
		if !strings.HasPrefix(opt.Env, envPrefix) {
			continue
		}
		// Strip both with and without prefix.
		_ = os.Unsetenv(opt.Env)
		_ = os.Unsetenv(strings.TrimPrefix(opt.Env, envPrefix))
	}

	// Unset the Kaniko environment variable which we set it in the
	// Dockerfile to ensure correct behavior during building.
	_ = os.Unsetenv("KANIKO_DIR")
}
