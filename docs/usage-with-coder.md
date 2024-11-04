# Usage with Coder

Coder provides sample
[Docker](https://github.com/coder/coder/tree/main/examples/templates/devcontainer-docker)
and
[Kubernetes](https://github.com/coder/coder/tree/main/examples/templates/devcontainer-kubernetes)
templates for use with Envbuilder. You can import these templates and modify them to fit
your specific requirements.

Below are some specific points to be aware of when using Envbuilder with a Coder
deployment:

- The `ENVBUILDER_INIT_SCRIPT` should execute `coder_agent.main.init_script` in
  order for you to be able to connect to your workspace.
- In order for the Agent init script to be able to fetch the agent binary from
  your Coder deployment, the resulting Devcontainer must contain a download tool
  such as `curl`, `wget`, or `busybox`.
- `CODER_AGENT_TOKEN` should be included in the environment variables for the
  Envbuilder container. You can also set `CODER_AGENT_URL` if required.

## Git Branch Selection

Choose a branch using `ENVBUILDER_GIT_URL` with a _ref/heads_ reference. For instance:

```
ENVBUILDER_GIT_URL=https://github.com/coder/envbuilder-starter-devcontainer/#refs/heads/my-feature-branch
```
