# Git Authentication

Two methods of authentication are supported:

## HTTP Authentication

If `ENVBUILDER_GIT_URL` starts with `http://` or `https://`, envbuilder will
authenticate with `ENVBUILDER_GIT_USERNAME` and `ENVBUILDER_GIT_PASSWORD`, if set.

For access token-based authentication, follow the following schema (if empty, there's no need to provide the field):

| Provider     | `ENVBUILDER_GIT_USERNAME` | `ENVBUILDER_GIT_PASSWORD` |
| ------------ | ------------------------- | ------------------------- |
| GitHub       | [access-token]            |                           |
| GitLab       | oauth2                    | [access-token]            |
| BitBucket    | x-token-auth              | [access-token]            |
| Azure DevOps | [access-token]            |                           |

If using envbuilder inside of [Coder](https://github.com/coder/coder), you can use the `coder_external_auth` Terraform resource to automatically provide this token on workspace creation:

```hcl
data "coder_external_auth" "github" {
    id = "github"
}

resource "docker_container" "dev" {
    env = [
        ENVBUILDER_GIT_USERNAME = data.coder_external_auth.github.access_token,
    ]
}
```

## SSH Authentication

If `ENVBUILDER_GIT_URL` does not start with `http://` or `https://`,
envbuilder will assume SSH authentication. You have the following options:

1. Public/Private key authentication: set `ENVBUILDER_GIT_SSH_PRIVATE_KEY_PATH` to the path of an
   SSH private key mounted inside the container. Envbuilder will use this SSH
   key to authenticate. Example:

   ```bash
    docker run -it --rm \
      -v /tmp/envbuilder:/workspaces \
      -e ENVBUILDER_GIT_URL=git@example.com:path/to/private/repo.git \
      -e ENVBUILDER_INIT_SCRIPT=bash \
      -e ENVBUILDER_GIT_SSH_PRIVATE_KEY_PATH=/.ssh/id_rsa \
      -v /home/user/id_rsa:/.ssh/id_rsa \
      ghcr.io/coder/envbuilder
   ```

    Alternatively, you can set `ENVBUILDER_GIT_SSH_PRIVATE_KEY_BASE64` to the
    base64-encoded content of your private key. Example:

    ```bash
    docker run -it --rm \
        -v /tmp/envbuilder:/workspaces \
        -e ENVBUILDER_GIT_URL=git@example.com:path/to/private/repo.git \
        -e ENVBUILDER_INIT_SCRIPT=bash \
        -e ENVBUILDER_GIT_SSH_PRIVATE_KEY_BASE64=$(base64 < ~/.ssh/id_ed25519) \
        ghcr.io/coder/envbuilder
    ```

1. Agent-based authentication: set `SSH_AUTH_SOCK` and mount in your agent socket, for example:

```bash
  docker run -it --rm \
    -v /tmp/envbuilder:/workspaces \
    -e ENVBUILDER_GIT_URL=git@example.com:path/to/private/repo.git \
    -e ENVBUILDER_INIT_SCRIPT=bash \
    -e SSH_AUTH_SOCK=/tmp/ssh-auth-sock \
    -v $SSH_AUTH_SOCK:/tmp/ssh-auth-sock \
    ghcr.io/coder/envbuilder
```

> Note: by default, envbuilder will accept and log all host keys. If you need
> strict host key checking, set `SSH_KNOWN_HOSTS` and mount in a `known_hosts`
> file.
