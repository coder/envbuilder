
# Environment Variables

| Flag | Environment variable | Default | Description |
| - | - | - | - |
| `--setup-script` | `ENVBUILDER_SETUP_SCRIPT` |  | The script to run before the init script. It runs as the root user regardless of the user specified in the devcontainer.json file. SetupScript is ran as the root user prior to the init script. It is used to configure envbuilder dynamically during the runtime. e.g. specifying whether to start systemd or tiny init for PID 1. |
| `--init-script` | `ENVBUILDER_INIT_SCRIPT` |  | The script to run to initialize the workspace. Default: `sleep infinity`. |
| `--init-command` | `ENVBUILDER_INIT_COMMAND` |  | The command to run to initialize the workspace. Default: `/bin/sh`. |
| `--init-args` | `ENVBUILDER_INIT_ARGS` |  | The arguments to pass to the init command. They are split according to /bin/sh rules with https://github.com/kballard/go-shellquote. |
| `--cache-repo` | `ENVBUILDER_CACHE_REPO` |  | The name of the container registry to push the cache image to. If this is empty, the cache will not be pushed. |
| `--base-image-cache-dir` | `ENVBUILDER_BASE_IMAGE_CACHE_DIR` |  | The path to a directory where the base image can be found. This should be a read-only directory solely mounted for the purpose of caching the base image. |
| `--layer-cache-dir` | `ENVBUILDER_LAYER_CACHE_DIR` |  | The path to a directory where built layers will be stored. This spawns an in-memory registry to serve the layers from. |
| `--devcontainer-dir` | `ENVBUILDER_DEVCONTAINER_DIR` |  | The path to the folder containing the devcontainer.json file that will be used to build the workspace and can either be an absolute path or a path relative to the workspace folder. If not provided, defaults to `.devcontainer`. |
| `--devcontainer-json-path` | `ENVBUILDER_DEVCONTAINER_JSON_PATH` |  | The path to a devcontainer.json file that is either an absolute path or a path relative to DevcontainerDir. This can be used in cases where one wants to substitute an edited devcontainer.json file for the one that exists in the repo. |
| `--dockerfile-path` | `ENVBUILDER_DOCKERFILE_PATH` |  | The relative path to the Dockerfile that will be used to build the workspace. This is an alternative to using a devcontainer that some might find simpler. |
| `--build-context-path` | `ENVBUILDER_BUILD_CONTEXT_PATH` |  | Can be specified when a DockerfilePath is specified outside the base WorkspaceFolder. This path MUST be relative to the WorkspaceFolder path into which the repo is cloned. |
| `--cache-ttl-days` | `ENVBUILDER_CACHE_TTL_DAYS` |  | The number of days to use cached layers before expiring them. Defaults to 7 days. |
| `--docker-config-base64` | `ENVBUILDER_DOCKER_CONFIG_BASE64` |  | The base64 encoded Docker config file that will be used to pull images from private container registries. When this is set, Docker configuration set via the DOCKER_CONFIG environment variable is ignored. |
| `--fallback-image` | `ENVBUILDER_FALLBACK_IMAGE` |  | Specifies an alternative image to use when neither an image is declared in the devcontainer.json file nor a Dockerfile is present. If there's a build failure (from a faulty Dockerfile) or a misconfiguration, this image will be the substitute. Set ExitOnBuildFailure to true to halt the container if the build faces an issue. |
| `--exit-on-build-failure` | `ENVBUILDER_EXIT_ON_BUILD_FAILURE` |  | Terminates the container upon a build failure. This is handy when preferring the FALLBACK_IMAGE in cases where no devcontainer.json or image is provided. However, it ensures that the container stops if the build process encounters an error. |
| `--exit-on-push-failure` | `ENVBUILDER_EXIT_ON_PUSH_FAILURE` |  | ExitOnPushFailure terminates the container upon a push failure. This is useful if failure to push the built image should abort execution and result in an error. |
| `--force-safe` | `ENVBUILDER_FORCE_SAFE` |  | Ignores any filesystem safety checks. This could cause serious harm to your system! This is used in cases where bypass is needed to unblock customers. |
| `--insecure` | `ENVBUILDER_INSECURE` |  | Bypass TLS verification when cloning and pulling from container registries. |
| `--ignore-paths` | `ENVBUILDER_IGNORE_PATHS` |  | The comma separated list of paths to ignore when building the workspace. |
| `--build-secrets` | `ENVBUILDER_BUILD_SECRETS` |  | The list of secret environment variables to use when building the image. |
| `--skip-rebuild` | `ENVBUILDER_SKIP_REBUILD` |  | Skip building if the MagicFile exists. This is used to skip building when a container is restarting. e.g. docker stop -> docker start This value can always be set to true - even if the container is being started for the first time. |
| `--skip-unused-stages` | `ENVBUILDER_SKIP_UNUSED_STAGES` |  | Skip building all unused docker stages. Otherwise it builds by default all stages, even the unnecessary ones until it reaches the target stage / end of Dockerfile. |
| `--git-url` | `ENVBUILDER_GIT_URL` |  | The URL of a Git repository containing a Devcontainer or Docker image to clone. This is optional. |
| `--git-clone-depth` | `ENVBUILDER_GIT_CLONE_DEPTH` |  | The depth to use when cloning the Git repository. |
| `--git-clone-single-branch` | `ENVBUILDER_GIT_CLONE_SINGLE_BRANCH` |  | Clone only a single branch of the Git repository. |
| `--git-username` | `ENVBUILDER_GIT_USERNAME` |  | The username to use for Git authentication. This is optional. |
| `--git-password` | `ENVBUILDER_GIT_PASSWORD` |  | The password to use for Git authentication. This is optional. |
| `--git-ssh-private-key-path` | `ENVBUILDER_GIT_SSH_PRIVATE_KEY_PATH` |  | Path to an SSH private key to be used for Git authentication. If this is set, then GIT_SSH_PRIVATE_KEY_BASE64 cannot be set. |
| `--git-ssh-private-key-base64` | `ENVBUILDER_GIT_SSH_PRIVATE_KEY_BASE64` |  | Base64 encoded SSH private key to be used for Git authentication. If this is set, then GIT_SSH_PRIVATE_KEY_PATH cannot be set. |
| `--git-http-proxy-url` | `ENVBUILDER_GIT_HTTP_PROXY_URL` |  | The URL for the HTTP proxy. This is optional. |
| `--workspace-base-dir` | `ENVBUILDER_WORKSPACE_BASE_DIR` | `/workspaces` | The path under which workspaces will be placed when workspace folder option is not given. |
| `--workspace-folder` | `ENVBUILDER_WORKSPACE_FOLDER` |  | The path to the workspace folder that will be built. This is optional. Defaults to `[workspace base dir]/[name]` where name is the name of the repository or `empty`. |
| `--ssl-cert-base64` | `ENVBUILDER_SSL_CERT_BASE64` |  | The content of an SSL cert file. This is useful for self-signed certificates. |
| `--export-env-file` | `ENVBUILDER_EXPORT_ENV_FILE` |  | Optional file path to a .env file where envbuilder will dump environment variables from devcontainer.json and the built container image. |
| `--post-start-script-path` | `ENVBUILDER_POST_START_SCRIPT_PATH` |  | The path to a script that will be created by envbuilder based on the postStartCommand in devcontainer.json, if any is specified (otherwise the script is not created). If this is set, the specified InitCommand should check for the presence of this script and execute it after successful startup. |
| `--coder-agent-url` | `CODER_AGENT_URL` |  | URL of the Coder deployment. If CODER_AGENT_TOKEN is also set, logs from envbuilder will be forwarded here and will be visible in the workspace build logs. |
| `--coder-agent-token` | `CODER_AGENT_TOKEN` |  | Authentication token for a Coder agent. If this is set, then CODER_AGENT_URL must also be set. |
| `--coder-agent-subsystem` | `CODER_AGENT_SUBSYSTEM` |  | Coder agent subsystems to report when forwarding logs. The envbuilder subsystem is always included. |
| `--push-image` | `ENVBUILDER_PUSH_IMAGE` |  | Push the built image to a remote registry. This option forces a reproducible build. |
| `--get-cached-image` | `ENVBUILDER_GET_CACHED_IMAGE` |  | Print the digest of the cached image, if available. Exits with an error if not found. |
| `--remote-repo-build-mode` | `ENVBUILDER_REMOTE_REPO_BUILD_MODE` | `false` | Use the remote repository as the source of truth when building the image. Enabling this option ignores user changes to local files and they will not be reflected in the image. This can be used to improving cache utilization when multiple users are building working on the same repository. |
| `--verbose` | `ENVBUILDER_VERBOSE` |  | Enable verbose logging. |
