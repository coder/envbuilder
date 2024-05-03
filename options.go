package envbuilder

import (
	"net/url"
	"strings"

	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/serpent"
	"github.com/go-git/go-billy/v5"
)

type LoggerFunc func(level codersdk.LogLevel, format string, args ...interface{})

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
	// SkipRebuild skips building if the MagicFile exists. This is used to skip
	// building when a container is restarting. e.g. docker stop -> docker start
	// This value can always be set to true - even if the container is being
	// started for the first time.
	SkipRebuild bool
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
	// GitHTTPProxyURL is the URL for the HTTP proxy. This is optional.
	GitHTTPProxyURL string
	// WorkspaceFolder is the path to the workspace folder that will be built.
	// This is optional.
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
	Logger LoggerFunc
	// Filesystem is the filesystem to use for all operations. Defaults to the
	// host filesystem.
	Filesystem billy.Filesystem
	// These options are specifically used when envbuilder is invoked as part of a
	// Coder workspace.
	CoderAgentURL *url.URL
	// CoderAgentToken is the authentication token for a Coder agent.
	CoderAgentToken string
	// CoderAgentSubsystem is the Coder agent subsystems to report when forwarding
	// logs. The envbuilder subsystem is always included.
	CoderAgentSubsystem []string
}

// Generate CLI options for the envbuilder command.
func (o *Options) CLI() serpent.OptionSet {
	return serpent.OptionSet{
		{
			Flag:  "setup-script",
			Env:   "SETUP_SCRIPT",
			Value: serpent.StringOf(&o.SetupScript),
			Description: "The script to run before the init script. It runs as " +
				"the root user regardless of the user specified in the devcontainer.json " +
				"file. SetupScript is ran as the root user prior to the init script. " +
				"It is used to configure envbuilder dynamically during the runtime. e.g. " +
				"specifying whether to start systemd or tiny init for PID 1.",
		},
		{
			Flag:        "init-script",
			Env:         "INIT_SCRIPT",
			Default:     "sleep infinity",
			Value:       serpent.StringOf(&o.InitScript),
			Description: "The script to run to initialize the workspace.",
		},
		{
			Flag:        "init-command",
			Env:         "INIT_COMMAND",
			Default:     "/bin/sh",
			Value:       serpent.StringOf(&o.InitCommand),
			Description: "The command to run to initialize the workspace.",
		},
		{
			Flag:  "init-args",
			Env:   "INIT_ARGS",
			Value: serpent.StringOf(&o.InitArgs),
			Description: "The arguments to pass to the init command. They are " +
				"split according to /bin/sh rules with " +
				"https://github.com/kballard/go-shellquote.",
		},
		{
			Flag:  "cache-repo",
			Env:   "CACHE_REPO",
			Value: serpent.StringOf(&o.CacheRepo),
			Description: "The name of the container registry to push the cache " +
				"image to. If this is empty, the cache will not be pushed.",
		},
		{
			Flag:  "base-image-cache-dir",
			Env:   "BASE_IMAGE_CACHE_DIR",
			Value: serpent.StringOf(&o.BaseImageCacheDir),
			Description: "The path to a directory where the base image " +
				"can be found. This should be a read-only directory solely mounted " +
				"for the purpose of caching the base image.",
		},
		{
			Flag:  "layer-cache-dir",
			Env:   "LAYER_CACHE_DIR",
			Value: serpent.StringOf(&o.LayerCacheDir),
			Description: "The path to a directory where built layers will " +
				"be stored. This spawns an in-memory registry to serve the layers " +
				"from.",
		},
		{
			Flag:  "devcontainer-dir",
			Env:   "DEVCONTAINER_DIR",
			Value: serpent.StringOf(&o.DevcontainerDir),
			Description: "The path to the folder containing the " +
				"devcontainer.json file that will be used to build the workspace " +
				"and can either be an absolute path or a path relative to the " +
				"workspace folder. If not provided, defaults to `.devcontainer`.",
		},
		{
			Flag:  "devcontainer-json-path",
			Env:   "DEVCONTAINER_JSON_PATH",
			Value: serpent.StringOf(&o.DevcontainerJSONPath),
			Description: "The path to a devcontainer.json file that " +
				"is either an absolute path or a path relative to DevcontainerDir. " +
				"This can be used in cases where one wants to substitute an edited " +
				"devcontainer.json file for the one that exists in the repo.",
		},
		{
			Flag:  "dockerfile-path",
			Env:   "DOCKERFILE_PATH",
			Value: serpent.StringOf(&o.DockerfilePath),
			Description: "The relative path to the Dockerfile that will " +
				"be used to build the workspace. This is an alternative to using " +
				"a devcontainer that some might find simpler.",
		},
		{
			Flag:  "build-context-path",
			Env:   "BUILD_CONTEXT_PATH",
			Value: serpent.StringOf(&o.BuildContextPath),
			Description: "Can be specified when a DockerfilePath is " +
				"specified outside the base WorkspaceFolder. This path MUST be " +
				"relative to the WorkspaceFolder path into which the repo is cloned.",
		},
		{
			Flag:  "cache-ttl-days",
			Env:   "CACHE_TTL_DAYS",
			Value: serpent.Int64Of(&o.CacheTTLDays),
			Description: "The number of days to use cached layers before " +
				"expiring them. Defaults to 7 days.",
		},
		{
			Flag:  "docker-config-base64",
			Env:   "DOCKER_CONFIG_BASE64",
			Value: serpent.StringOf(&o.DockerConfigBase64),
			Description: "The base64 encoded Docker config file that " +
				"will be used to pull images from private container registries.",
		},
		{
			Flag:  "fallback-image",
			Env:   "FALLBACK_IMAGE",
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
			Env:   "EXIT_ON_BUILD_FAILURE",
			Value: serpent.BoolOf(&o.ExitOnBuildFailure),
			Description: "Terminates the container upon a build failure. " +
				"This is handy when preferring the FALLBACK_IMAGE in cases where " +
				"no devcontainer.json or image is provided. However, it ensures " +
				"that the container stops if the build process encounters an error.",
		},
		{
			Flag:  "force-safe",
			Env:   "FORCE_SAFE",
			Value: serpent.BoolOf(&o.ForceSafe),
			Description: "Ignores any filesystem safety checks. This could cause " +
				"serious harm to your system! This is used in cases where bypass " +
				"is needed to unblock customers.",
		},
		{
			Flag:  "insecure",
			Env:   "INSECURE",
			Value: serpent.BoolOf(&o.Insecure),
			Description: "Bypass TLS verification when cloning and pulling from " +
				"container registries.",
		},
		{
			Flag:    "ignore-paths",
			Env:     "IGNORE_PATHS",
			Value:   serpent.StringArrayOf(&o.IgnorePaths),
			Default: "/var/run",
			Description: "The comma separated list of paths to ignore when " +
				"building the workspace.",
		},
		{
			Flag:  "skip-rebuild",
			Env:   "SKIP_REBUILD",
			Value: serpent.BoolOf(&o.SkipRebuild),
			Description: "Skip building if the MagicFile exists. This is used " +
				"to skip building when a container is restarting. e.g. docker stop -> " +
				"docker start This value can always be set to true - even if the " +
				"container is being started for the first time.",
		},
		{
			Flag:        "git-url",
			Env:         "GIT_URL",
			Value:       serpent.StringOf(&o.GitURL),
			Description: "The URL of the Git repository to clone. This is optional.",
		},
		{
			Flag:        "git-clone-depth",
			Env:         "GIT_CLONE_DEPTH",
			Value:       serpent.Int64Of(&o.GitCloneDepth),
			Description: "The depth to use when cloning the Git repository.",
		},
		{
			Flag:        "git-clone-single-branch",
			Env:         "GIT_CLONE_SINGLE_BRANCH",
			Value:       serpent.BoolOf(&o.GitCloneSingleBranch),
			Description: "Clone only a single branch of the Git repository.",
		},
		{
			Flag:        "git-username",
			Env:         "GIT_USERNAME",
			Value:       serpent.StringOf(&o.GitUsername),
			Description: "The username to use for Git authentication. This is optional.",
		},
		{
			Flag:        "git-password",
			Env:         "GIT_PASSWORD",
			Value:       serpent.StringOf(&o.GitPassword),
			Description: "The password to use for Git authentication. This is optional.",
		},
		{
			Flag:        "git-ssh-private-key-path",
			Env:         "GIT_SSH_PRIVATE_KEY_PATH",
			Value:       serpent.StringOf(&o.GitSSHPrivateKeyPath),
			Description: "Path to an SSH private key to be used for Git authentication.",
		},
		{
			Flag:        "git-http-proxy-url",
			Env:         "GIT_HTTP_PROXY_URL",
			Value:       serpent.StringOf(&o.GitHTTPProxyURL),
			Description: "The URL for the HTTP proxy. This is optional.",
		},
		{
			Flag:  "workspace-folder",
			Env:   "WORKSPACE_FOLDER",
			Value: serpent.StringOf(&o.WorkspaceFolder),
			Description: "The path to the workspace folder that will " +
				"be built. This is optional.",
		},
		{
			Flag:  "ssl-cert-base64",
			Env:   "SSL_CERT_BASE64",
			Value: serpent.StringOf(&o.SSLCertBase64),
			Description: "The content of an SSL cert file. This is useful " +
				"for self-signed certificates.",
		},
		{
			Flag:  "export-env-file",
			Env:   "EXPORT_ENV_FILE",
			Value: serpent.StringOf(&o.ExportEnvFile),
			Description: "Optional file path to a .env file where " +
				"envbuilder will dump environment variables from devcontainer.json " +
				"and the built container image.",
		},
		{
			Flag:  "post-start-script-path",
			Env:   "POST_START_SCRIPT_PATH",
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
			Value: serpent.URLOf(o.CoderAgentURL),
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
	}
}

func (o *Options) Markdown() string {
	cliOptions := o.CLI()
	var sb strings.Builder
	_, _ = sb.WriteString("| Flag | Environment variable | Default | Description |\n")
	_, _ = sb.WriteString("| - | - | - | - |\n")

	for _, opt := range cliOptions {
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
