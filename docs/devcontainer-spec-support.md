# Support for Dev Container Specification

> Refer to the full Dev Container specification [here](https://containers.dev/implementors/json_reference/) for more information on the below options.

The symbols in the first column indicate the support status:

- 🟢 Fully supported.
- 🟠 Partially supported.
- 🔴 Not currently supported.

The last column indicates any currently existing GitHub issue for tracking support for this feature.
Feel free to [create a new issue](https://github.com/coder/envbuilder/issues/new) if you'd like Envbuilder to support a particular feature.

## General

| Status | Name                          | Description                                                                                                                                                                           | Known Issues                                                       |
| ------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| 🔴     | `name`                        | Human-friendly name for the dev container.                                                                                                                                            | -                                                                  |
| 🔴     | `forwardPorts`                | Port forwarding allows exposing container ports to the host, making services accessible.                                                                                              | [#48](https://github.com/coder/envbuilder/issues/48)               |
| 🔴     | `portsAttributes`             | Set port attributes for a `host:port`.                                                                                                                                                | -                                                                  |
| 🔴     | `otherPortsAttributes`        | Other options for ports not configured using `portsAttributes`.                                                                                                                       | -                                                                  |
| 🟢     | `containerEnv`                | Environment variables to set inside the container.                                                                                                                                    | -                                                                  |
| 🟢     | `remoteEnv`                   | Override environment variables for tools, but not the whole container.                                                                                                                | -                                                                  |
| 🟢\*   | `remoteUser`                  | Override the user for tools, but not the whole container. <br/>\*_Refer to [choosing a target user](./users.md#choosing-a-target-user), as behaviour may diverge from the spec._      | -                                                                  |
| 🟢\*   | `containerUser`               | Override the user for all operations run inside the container. <br/>\*_Refer to [choosing a target user](./users.md#choosing-a-target-user), as behaviour may diverge from the spec._ | -                                                                  |
| 🔴     | `updateRemoteUserUID`         | Update the devcontainer UID/GID to match the local user.                                                                                                                              | -                                                                  |
| 🔴     | `userEnvProbe`                | Shell to use when probing for user environment variables.                                                                                                                             | -                                                                  |
| 🔴     | `overrideCommand`             | Override the default sleep command to be run by supporting services.                                                                                                                  | -                                                                  |
| 🔴     | `shutdownAction`              | Action to take when supporting tools are closed or shut down.                                                                                                                         | -                                                                  |
| 🔴     | `init`                        | Adds a tiny init process to the container.                                                                                                                                            | [#221](https://github.com/coder/envbuilder/issues/221)             |
| 🔴     | `privileged`                  | Whether the container should be run in privileged mode.                                                                                                                               | -                                                                  |
| 🔴     | `capAdd`                      | Capabilities to add to the container (for example, `SYS_PTRACE`).                                                                                                                     | -                                                                  |
| 🔴     | `securityOpt`                 | Security options to add to the container (for example, `seccomp=unconfined`).                                                                                                         | -                                                                  |
| 🔴     | `mounts`                      | Add additional mounts to the container.                                                                                                                                               | [#220](https://github.com/coder/envbuilder/issues/220)             |
| 🟢     | `features`                    | Features to be added to the devcontainer.                                                                                                                                             | -                                                                  |
| 🔴     | `overrideFeatureInstallOrder` | Override the order in which features should be installed.                                                                                                                             | [#226](https://github.com/coder/envbuilder/issues/226)             |
| 🟠     | `customizations`              | Product-specific properties, e.g., _VS Code_ settings and extensions.                                                                                                                 | Workaround in [#43](https://github.com/coder/envbuilder/issues/43) |

## Image or Dockerfile

| Status | Name               | Description                                                                                                   | Known Issues |
| ------ | ------------------ | ------------------------------------------------------------------------------------------------------------- | ------------ |
| 🟢     | `image`            | Name of an image to run.                                                                                      | -            |
| 🟢     | `build.dockerfile` | Path to a Dockerfile to build relative to `devcontainer.json`.                                                | -            |
| 🟢     | `build.context`    | Path to the build context relative to `devcontainer.json`.                                                    | -            |
| 🟢     | `build.args`       | Build args to use when building the Dockerfile.                                                               | -            |
| 🔴     | `build.options`    | Build options to pass to the Docker daemon. Envbuilder does not use a Docker daemon, so this is not relevant. | -            |
| 🟢     | `build.target`     | Target to be passed when building the Dockerfile.                                                             | -            |
| 🟢     | `build.cacheFrom`  | Images to use as caches when building the Dockerfile.                                                         | -            |
| 🔴     | `appPort`          | Ports to be published locally when the container is running.                                                  | -            |
| 🔴     | `workspaceMount`   | Overrides the default local mount point for the workspace when the container is created.                      | -            |
| 🔴     | `workspaceFolder`  | Default path to open when connecting to the container.                                                        | -            |

## Docker Compose

| Status | Name                | Description                                                                  | Known Issues                                           |
| ------ | ------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------ |
| 🔴     | `dockerComposeFile` | Path to a Docker Compose file related to the `devcontainer.json`.            | [#236](https://github.com/coder/envbuilder/issues/236) |
| 🔴     | `service`           | Name of the Docker Compose service to which supporting tools should connect. | [#236](https://github.com/coder/envbuilder/issues/236) |
| 🔴     | `runServices`       | Docker Compose services to automatically start.                              | [#236](https://github.com/coder/envbuilder/issues/236) |

## Lifecycle Scripts

| Status | Name                   | Description                                                                                                                                                                                        | Known Issues                                           |
| ------ | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| 🔴     | `initializeCommand`    | Command to run on the host machine when creating the container.                                                                                                                                    | [#395](https://github.com/coder/envbuilder/issues/395) |
| 🟢     | `onCreateCommand`      | Command to run inside container after first start.                                                                                                                                                 |                                                        |
| 🟢     | `updateContentCommand` | Command to run after `onCreateCommand` inside container.                                                                                                                                           |                                                        |
| 🟢     | `postCreateCommand`    | Command to run after `updateContentCommand` inside container.                                                                                                                                      |                                                        |
| 🟢\*   | `postStartCommand`     | Command to run each time the container is started.<br/>\*_This may be specified by `ENVBUILDER_POST_START_SCRIPT`, in which case it is the responsibility of `ENVBUILDER_INIT_COMMAND` to run it._ |                                                        |
| 🔴     | `postAttachCommand`    | Command to run each time a tool attaches to the container.                                                                                                                                         |                                                        |
| 🔴     | `waitFor`              | Specify the lifecycle command tools should wait to complete before connecting.                                                                                                                     |                                                        |

## Minimum Host Requirements

| Status | Name                       | Description                      | Known Issues |
| ------ | -------------------------- | -------------------------------- | ------------ |
| 🔴     | `hostRequirements.cpus`    | Minimum number of CPUs required. | -            |
| 🔴     | `hostRequirements.memory`  | Minimum memory requirements.     | -            |
| 🔴     | `hostRequirements.storage` | Minimum storage requirements.    | -            |
| 🔴     | `hostRequirements.gpu`     | Whether a GPU is required.       | -            |

## Variable Substitution

| Status | Name                                  | Description                                         | Known Issues |
| ------ | ------------------------------------- | --------------------------------------------------- | ------------ |
| 🟢     | `${localEnv:VARIABLE_NAME}`           | Environment variable on the host machine.           | -            |
| 🟢     | `${containerEnv:VARIABLE_NAME}`       | Existing environment variable inside the container. | -            |
| 🟢     | `${localWorkspaceFolder}`             | Path to the local workspace folder.                 | -            |
| 🟢     | `${containerWorkspaceFolder}`         | Path to the workspace folder inside the container.  | -            |
| 🟢     | `${localWorkspaceFolderBasename}`     | Base name of `localWorkspaceFolder`.                | -            |
| 🟢     | `${containerWorkspaceFolderBasename}` | Base name of `containerWorkspaceFolder`.            | -            |
| 🔴     | `${devcontainerId}`                   | A stable unique identifier for the devcontainer.    | -            |

## Features

| Status | Name                     | Description                                                  | Known Issues |
| ------ | ------------------------ | ------------------------------------------------------------ | ------------ |
| 🟢     | `id`                     | Feature identifier                                           | -            |
| �      | `version`                | Feature version                                              | -            |
| 🟢     | `name`                   | Feature version                                              | -            |
| 🟢     | `description`            | Description                                                  | -            |
| 🟢     | `documentationURL`       | Feature documentation URL                                    | -            |
| 🟢     | `licenseURL`             | Feature license URL                                          | -            |
| 🟢     | `keywords`               | Feature keywords                                             | -            |
| 🟢     | `options`                | Map of options passed to the feature                         | -            |
| 🟢     | `options[*].type`        | Types of the option                                          | -            |
| 🟢     | `options[*].proposals`   | Suggested values of the option                               | -            |
| 🟢     | `options[*].enum`        | Allowed string values of the option                          | -            |
| 🟢     | `options[*].default`     | Default value of the option                                  | -            |
| 🟢     | `options[*].description` | Description of the option                                    | -            |
| 🟢     | `containerEnv`           | Environment variables to override                            | -            |
| 🔴     | `privileged`             | Set privileged mode for the container if the feature is used | -            |
| 🔴     | `init`                   | Add `tiny init` when the feature is used                     | -            |
| 🔴     | `capAdd`                 | Capabilities to add when the feature is used                 | -            |
| 🔴     | `securityOpt`            | Security options to add when the feature is used             | -            |
| 🔴     | `entrypoint`             | Override entrypoint when the feature is used                 | -            |
| 🔴     | `customizations`         | Product-specific properties to add when the feature is used  | -            |
| 🔴     | `dependsOn`              | Define a hard dependency on other features                   | -            |
| 🔴     | `installsAfter`          | Define a soft dependency on other features                   | -            |
| 🔴     | `legacyIds`              | Used when renaming a feature                                 | -            |
| 🔴     | `deprecated`             | Whether the feature is deprecated                            | -            |
| 🔴     | `mounts`                 | Cross-orchestrator mounts to add to the container            | -            |
