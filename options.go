package envbuilder

import (
	"github.com/coder/serpent"
)

// Options contains the configuration for the envbuilder.
type Options struct {
	SetupScript          string
	InitScript           string
	InitCommand          string
	InitArgs             string
	CacheRepo            string
	BaseImageCacheDir    string
	LayerCacheDir        string
	DevcontainerDir      string
	DevcontainerJSONPath string
	DockerfilePath       string
	BuildContextPath     string
	CacheTTLDays         int64
	DockerConfigBase64   string
	FallbackImage        string
	ExitOnBuildFailure   bool
	ForceSafe            bool
	Insecure             bool
	IgnorePaths          []string
	SkipRebuild          bool
	GitURL               string
	GitCloneDepth        int64
	GitCloneSingleBranch bool
	GitUsername          string
	GitPassword          string
	GitHTTPProxyURL      string
	WorkspaceFolder      string
	SSLCertBase64        string
	ExportEnvFile        string
	PostStartScriptPath  string
}

// Generate CLI options for the envbuilder command.
func (o *Options) CLI() serpent.OptionSet {
	return serpent.OptionSet{
		{
			Flag:  "setup-script",
			Env:   "SETUP_SCRIPT",
			Value: serpent.StringOf(&o.SetupScript),
			Description: "SetupScript is the script to run before the init script. It runs as " +
				"the root user regardless of the user specified in the devcontainer.json " +
				"file.\n\nSetupScript is ran as the root user prior to the init script. " +
				"It is used to configure envbuilder dynamically during the runtime. e.g. " +
				"specifying whether to start systemd or tiny init for PID 1.",
		},
		{
			Flag:        "init-script",
			Env:         "INIT_SCRIPT",
			Default:     "sleep infinity",
			Value:       serpent.StringOf(&o.InitScript),
			Description: "InitScript is the script to run to initialize the workspace.",
		},
		{
			Flag:        "init-command",
			Env:         "INIT_COMMAND",
			Default:     "/bin/sh",
			Value:       serpent.StringOf(&o.InitCommand),
			Description: "InitCommand is the command to run to initialize the workspace.",
		},
		{
			Flag:  "init-args",
			Env:   "INIT_ARGS",
			Value: serpent.StringOf(&o.InitArgs),
			Description: "InitArgs are the arguments to pass to the init command. They are " +
				"split according to /bin/sh rules with " +
				"https://github.com/kballard/go-shellquote.",
		},
		{
			Flag:  "cache-repo",
			Env:   "CACHE_REPO",
			Value: serpent.StringOf(&o.CacheRepo),
			Description: "CacheRepo is the name of the container registry to push the cache " +
				"image to. If this is empty, the cache will not be pushed.",
		},
		{
			Flag:  "base-image-cache-dir",
			Env:   "BASE_IMAGE_CACHE_DIR",
			Value: serpent.StringOf(&o.BaseImageCacheDir),
			Description: "BaseImageCacheDir is the path to a directory where the base image " +
				"can be found. This should be a read-only directory solely mounted " +
				"for the purpose of caching the base image.",
		},
		{
			Flag:  "layer-cache-dir",
			Env:   "LAYER_CACHE_DIR",
			Value: serpent.StringOf(&o.LayerCacheDir),
			Description: "LayerCacheDir is the path to a directory where built layers will " +
				"be stored. This spawns an in-memory registry to serve the layers " +
				"from.",
		},
		{
			Flag:  "devcontainer-dir",
			Env:   "DEVCONTAINER_DIR",
			Value: serpent.StringOf(&o.DevcontainerDir),
			Description: "DevcontainerDir is a path to the folder containing the " +
				"devcontainer.json file that will be used to build the workspace " +
				"and can either be an absolute path or a path relative to the " +
				"workspace folder. If not provided, defaults to `.devcontainer`.",
		},
		{
			Flag:  "devcontainer-json-path",
			Env:   "DEVCONTAINER_JSON_PATH",
			Value: serpent.StringOf(&o.DevcontainerJSONPath),
			Description: "DevcontainerJSONPath is a path to a devcontainer.json file that " +
				"is either an absolute path or a path relative to DevcontainerDir. " +
				"This can be used in cases where one wants to substitute an edited " +
				"devcontainer.json file for the one that exists in the repo.",
		},
		{
			Flag:  "dockerfile-path",
			Env:   "DOCKERFILE_PATH",
			Value: serpent.StringOf(&o.DockerfilePath),
			Description: "DockerfilePath is a relative path to the Dockerfile that will " +
				"be used to build the workspace. This is an alternative to using " +
				"a devcontainer that some might find simpler.",
		},
		{
			Flag:  "build-context-path",
			Env:   "BUILD_CONTEXT_PATH",
			Value: serpent.StringOf(&o.BuildContextPath),
			Description: "BuildContextPath can be specified when a DockerfilePath is " +
				"specified outside the base WorkspaceFolder. This path MUST be " +
				"relative to the WorkspaceFolder path into which the repo is cloned.",
		},
		{
			Flag:  "cache-ttl-days",
			Env:   "CACHE_TTL_DAYS",
			Value: serpent.Int64Of(&o.CacheTTLDays),
			Description: "CacheTTLDays is the number of days to use cached layers before " +
				"expiring them. Defaults to 7 days.",
		},
		{
			Flag:  "docker-config-base64",
			Env:   "DOCKER_CONFIG_BASE64",
			Value: serpent.StringOf(&o.DockerConfigBase64),
			Description: "DockerConfigBase64 is a base64 encoded Docker config file that " +
				"will be used to pull images from private container registries.",
		},
		{
			Flag:  "fallback-image",
			Env:   "FALLBACK_IMAGE",
			Value: serpent.StringOf(&o.FallbackImage),
			Description: "FallbackImage specifies an alternative image to use when neither " +
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
			Description: "ExitOnBuildFailure terminates the container upon a build failure. " +
				"This is handy when preferring the FALLBACK_IMAGE in cases where " +
				"no devcontainer.json or image is provided. However, it ensures " +
				"that the container stops if the build process encounters an error.",
		},
		{
			Flag:  "force-safe",
			Env:   "FORCE_SAFE",
			Value: serpent.BoolOf(&o.ForceSafe),
			Description: "ForceSafe ignores any filesystem safety checks. This could cause " +
				"serious harm to your system! This is used in cases where bypass " +
				"is needed to unblock customers.",
		},
		{
			Flag:  "insecure",
			Env:   "INSECURE",
			Value: serpent.BoolOf(&o.Insecure),
			Description: "Insecure bypasses TLS verification when cloning and pulling from " +
				"container registries.",
		},
		{
			Flag:    "ignore-paths",
			Env:     "IGNORE_PATHS",
			Value:   serpent.StringArrayOf(&o.IgnorePaths),
			Default: "/var/run",
			Description: "IgnorePaths is a comma separated list of paths to ignore when " +
				"building the workspace.",
		},
		{
			Flag:  "skip-rebuild",
			Env:   "SKIP_REBUILD",
			Value: serpent.BoolOf(&o.SkipRebuild),
			Description: "SkipRebuild skips building if the MagicFile exists. This is used " +
				"to skip building when a container is restarting. e.g. docker stop -> " +
				"docker start This value can always be set to true - even if the " +
				"container is being started for the first time.",
		},
		{
			Flag:        "git-url",
			Env:         "GIT_URL",
			Value:       serpent.StringOf(&o.GitURL),
			Description: "GitURL is the URL of the Git repository to clone. This is optional.",
		},
		{
			Flag:        "git-clone-depth",
			Env:         "GIT_CLONE_DEPTH",
			Value:       serpent.Int64Of(&o.GitCloneDepth),
			Description: "GitCloneDepth is the depth to use when cloning the Git repository.",
		},
		{
			Flag:        "git-clone-single-branch",
			Env:         "GIT_CLONE_SINGLE_BRANCH",
			Value:       serpent.BoolOf(&o.GitCloneSingleBranch),
			Description: "GitCloneSingleBranch clones only a single branch of the Git repository.",
		},
		{
			Flag:        "git-username",
			Env:         "GIT_USERNAME",
			Value:       serpent.StringOf(&o.GitUsername),
			Description: "GitUsername is the username to use for Git authentication. This is optional.",
		},
		{
			Flag:        "git-password",
			Env:         "GIT_PASSWORD",
			Value:       serpent.StringOf(&o.GitPassword),
			Description: "GitPassword is the password to use for Git authentication. This is optional.",
		},
		{
			Flag:        "git-http-proxy-url",
			Env:         "GIT_HTTP_PROXY_URL",
			Value:       serpent.StringOf(&o.GitHTTPProxyURL),
			Description: "GitHTTPProxyURL is the url for the http proxy. This is optional.",
		},
		{
			Flag:  "workspace-folder",
			Env:   "WORKSPACE_FOLDER",
			Value: serpent.StringOf(&o.WorkspaceFolder),
			Description: "WorkspaceFolder is the path to the workspace folder that will " +
				"be built. This is optional.",
		},
		{
			Flag:  "ssl-cert-base64",
			Env:   "SSL_CERT_BASE64",
			Value: serpent.StringOf(&o.SSLCertBase64),
			Description: "SSLCertBase64 is the content of an SSL cert file. This is useful " +
				"for self-signed certificates.",
		},
		{
			Flag:  "export-env-file",
			Env:   "EXPORT_ENV_FILE",
			Value: serpent.StringOf(&o.ExportEnvFile),
			Description: "ExportEnvFile is an optional file path to a .env file where " +
				"envbuilder will dump environment variables from devcontainer.json " +
				"and the built container image.",
		},
		{
			Flag:  "post-start-script-path",
			Env:   "POST_START_SCRIPT_PATH",
			Value: serpent.StringOf(&o.PostStartScriptPath),
			Description: "PostStartScriptPath is the path to a script that will be created " +
				"by envbuilder based on the postStartCommand in devcontainer.json, " +
				"if any is specified (otherwise the script is not created). If this " +
				"is set, the specified InitCommand should check for the presence of " +
				"this script and execute it after successful startup.",
		},
	}
}
