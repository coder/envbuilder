package envbuilder

import (
	"fmt"
	"strconv"
	"strings"
)

type option struct {
	Env    string
	Value  any
	Detail string
}

type OptionsMap map[string]option

var defaultOptions = OptionsMap{
	"SetupScript": option{
		Env:   "SETUP_SCRIPT",
		Value: "",
		Detail: `SetupScript is the script to run before the init script.
		It runs as the root user regardless of the user specified
		in the devcontainer.json file.
		
		SetupScript is ran as the root user prior to the init script.
		It is used to configure envbuilder dynamically during the runtime.
		e.g. specifying whether to start ` + "`systemd`" + ` or ` + "`tiny init`" + ` for PID 1.`,
	},
	"InitScript": option{
		Env:    "INIT_SCRIPT",
		Value:  "sleep infinity",
		Detail: "InitScript is the script to run to initialize the workspace.",
	},
	"InitCommand": option{
		Env:    "INIT_COMMAND",
		Value:  "/bin/sh",
		Detail: "InitCommand is the command to run to initialize the workspace.",
	},
	"InitArgs": option{
		Env:   "INIT_ARGS",
		Value: "",
		Detail: `InitArgs are the arguments to pass to the init command.
		They are split according to ` + "`/bin/sh`" + ` rules with
		https://github.com/kballard/go-shellquote`,
	},
	"CacheRepo": option{
		Env:   "CACHE_REPO",
		Value: "",
		Detail: `CacheRepo is the name of the container registry
		to push the cache image to. If this is empty, the cache
		will not be pushed.`,
	},
	"BaseImageCacheDir": option{
		Env:   "BASE_IMAGE_CACHE_DIR",
		Value: "",
		Detail: `BaseImageCacheDir is the path to a directory where the base
		image can be found. This should be a read-only directory
		solely mounted for the purpose of caching the base image.`,
	},
	"LayerCacheDir": option{
		Env:   "LAYER_CACHE_DIR",
		Value: "",
		Detail: `LayerCacheDir is the path to a directory where built layers
		will be stored. This spawns an in-memory registry to serve
		the layers from.`,
	},
	"DevcontainerDir": option{
		Env:   "DEVCONTAINER_DIR",
		Value: "",
		Detail: `DevcontainerDir is a path to the folder containing
		the devcontainer.json file that will be used to build the
		workspace and can either be an absolute path or a path
		relative to the workspace folder. If not provided, defaults to
		` + "`.devcontainer`" + `.`,
	},
	"DevcontainerJSONPath": option{
		Env:   "DEVCONTAINER_JSON_PATH",
		Value: "",
		Detail: `DevcontainerJSONPath is a path to a devcontainer.json file
		that is either an absolute path or a path relative to
		DevcontainerDir. This can be used in cases where one wants
		to substitute an edited devcontainer.json file for the one
		that exists in the repo.`,
	},
	"DockerfilePath": option{
		Env:   "DOCKERFILE_PATH",
		Value: "",
		Detail: `DockerfilePath is a relative path to the Dockerfile that
		will be used to build the workspace. This is an alternative
		to using a devcontainer that some might find simpler.`,
	},
	"CacheTTLDays": option{
		Env:   "CACHE_TTL_DAYS",
		Value: 0,
		Detail: `CacheTTLDays is the number of days to use cached layers before
		expiring them. Defaults to 7 days.`,
	},
	"DockerConfigBase64": option{
		Env:   "DOCKER_CONFIG_BASE64",
		Value: "",
		Detail: `DockerConfigBase64 is a base64 encoded Docker config
		file that will be used to pull images from private
		container registries.`,
	},
	"FallbackImage": option{
		Env:   "FALLBACK_IMAGE",
		Value: "",
		Detail: `FallbackImage specifies an alternative image to use when neither
		an image is declared in the devcontainer.json file nor a Dockerfile is present.
		If there's a build failure (from a faulty Dockerfile) or a misconfiguration,
		this image will be the substitute.
		Set ` + "`ExitOnBuildFailure`" + ` to true to halt the container if the build faces an issue.`,
	},
	"ExitOnBuildFailure": option{
		Env:   "EXIT_ON_BUILD_FAILURE",
		Value: false,
		Detail: `ExitOnBuildFailure terminates the container upon a build failure.
		This is handy when preferring the ` + "`FALLBACK_IMAGE`" + ` in cases where
		no devcontainer.json or image is provided. However, it ensures
		that the container stops if the build process encounters an error.`,
	},
	"ForceSafe": option{
		Env:   "FORCE_SAFE",
		Value: false,
		Detail: `ForceSafe ignores any filesystem safety checks.
		This could cause serious harm to your system!
		This is used in cases where bypass is needed
		to unblock customers!`,
	},
	"Insecure": option{
		Env:   "INSECURE",
		Value: false,
		Detail: `Insecure bypasses TLS verification when cloning
		and pulling from container registries.`,
	},
	"IgnorePaths": option{
		Env: "IGNORE_PATHS",
		// Kubernetes frequently stores secrets in /var/run/secrets, and
		// other applications might as well. This seems to be a sensible
		// default, but if that changes, it's simple to adjust.
		Value: []string{"/var/run"},
		Detail: `IgnorePaths is a comma separated list of paths
		to ignore when building the workspace.`,
	},
	"SkipRebuild": option{
		Env:   "SKIP_REBUILD",
		Value: false,
		Detail: `SkipRebuild skips building if the MagicFile exists.
		This is used to skip building when a container is
		restarting. e.g. docker stop -> docker start
		This value can always be set to true - even if the
		container is being started for the first time.`,
	},
	"GitURL": option{
		Env:   "GIT_URL",
		Value: "",
		Detail: `GitURL is the URL of the Git repository to clone.
		This is optional!`,
	},
	"GitCloneDepth": option{
		Env:   "GIT_CLONE_DEPTH",
		Value: 0,
		Detail: `GitCloneDepth is the depth to use when cloning
		the Git repository.`,
	},
	"GitCloneSingleBranch": option{
		Env:   "GIT_CLONE_SINGLE_BRANCH",
		Value: false,
		Detail: `GitCloneSingleBranch clones only a single branch
		of the Git repository.`,
	},
	"GitUsername": option{
		Env:   "GIT_USERNAME",
		Value: "",
		Detail: `GitUsername is the username to use for Git authentication.
		This is optional!`,
	},
	"GitPassword": option{
		Env:   "GIT_PASSWORD",
		Value: "",
		Detail: `GitPassword is the password to use for Git authentication.
		This is optional!`,
	},
	"GitHTTPProxyURL": option{
		Env:   "GIT_HTTP_PROXY_URL",
		Value: "",
		Detail: `GitHTTPProxyURL is the url for the http proxy.
		This is optional!`,
	},
	"WorkspaceFolder": option{
		Env:   "WORKSPACE_FOLDER",
		Value: "",
		Detail: `WorkspaceFolder is the path to the workspace folder
		that will be built. This is optional!`,
	},
	"SSLCertBase64": option{
		Env:   "SSL_CERT_BASE64",
		Value: "",
		Detail: `SSLCertBase64 is the content of an SSL cert file.
		This is useful for self-signed certificates.`,
	},
	"ExportEnvFile": option{
		Env:   "EXPORT_ENV_FILE",
		Value: "",
		Detail: `ExportEnvFile is an optional file path to a .env file where
		envbuilder will dump environment variables from devcontainer.json and
		the built container image.`,
	},
	"PostStartScriptPath": option{
		Env:   "POST_START_SCRIPT_PATH",
		Value: "",
		Detail: `PostStartScriptPath is the path to a script that will be created by
		envbuilder based on the ` + "`postStartCommand`" + ` in devcontainer.json, if any
		is specified (otherwise the script is not created). If this is set, the
		specified InitCommand should check for the presence of this script and
		execute it after successful startup.`,
	},
}

func OptionsFromEnv(getEnv func(string) (string, bool)) OptionsMap {
	options := defaultOptions

	for key, option := range options {
		value, ok := getEnv(option.Env)
		if !ok || value == "" {
			continue
		}

		switch v := options[key].Value.(type) {
		case string:
			options.SetString(key, value)
		case int:
			intValue, _ := strconv.Atoi(value)
			options.SetInt(key, intValue)
		case bool:
			boolValue, _ := strconv.ParseBool(value)
			options.SetBool(key, boolValue)
		case []string:
			options.SetStringSlice(key, strings.Split(value, ","))
		default:
			panic(fmt.Sprintf("unsupported type %T", v))
		}
	}

	return options
}

func (o OptionsMap) get(key string) any {
	val, ok := o[key]
	if !ok {
		panic(fmt.Sprintf("key %q not found in options", key))
	}
	return val.Value
}

func (o OptionsMap) GetString(key string) string {
	val := o.get(key)
	if val == nil {
		return ""
	}
	return val.(string)
}

func (o OptionsMap) GetBool(key string) bool {
	val := o.get(key)
	if val == nil {
		return false
	}
	return val.(bool)
}

func (o OptionsMap) GetInt(key string) int {
	val := o.get(key)
	if val == nil {
		return 0
	}
	return val.(int)
}

func (o OptionsMap) GetStringSlice(key string) []string {
	val := o.get(key)
	if val == nil {
		return nil
	}
	return val.([]string)
}

func (o OptionsMap) set(key string, value any) {
	val, ok := o[key]
	if !ok {
		panic(fmt.Sprintf("key %q not found in options", key))
	}
	val.Value = value
	o[key] = val
}

func (o OptionsMap) SetString(key string, value string) {
	o.set(key, value)
}

func (o OptionsMap) SetStringSlice(key string, value []string) {
	o.set(key, value)
}

func (o OptionsMap) SetBool(key string, value bool) {
	o.set(key, value)
}

func (o OptionsMap) SetInt(key string, value int) {
	o.set(key, value)
}
