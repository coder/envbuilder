FROM alpine:latest

# Show that we can use secrets as envs
RUN --mount=type=secret,id=FOO,env=FOO echo $FOO > /foo_env.txt
# Show that we can use secrets as files in the default location
RUN --mount=type=secret,id=FOO cat /run/secrets/FOO > /foo_from_default_file.txt
# Show that we can use secrets as files in a custom location
RUN --mount=type=secret,id=FOO,target=/foo_custom_secret_location.txt cat /foo_custom_secret_location.txt > /foo_from_custom_file.txt
# Show that secrets are only available to the commands that mount them (bar.txt should be empty)
RUN --mount=type=secret,id=BAR,env=BAR echo $FOO > /bar.txt