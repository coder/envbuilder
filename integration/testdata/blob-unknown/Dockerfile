FROM alpine:latest

# This will produce an empty layer via Docker. It will allow us to test for a
# conflicting empty layer produced by Kaniko. This is to check against the
# BLOB_UNKNOWN error when trying to upload the built image to a registry and
# Kaniko having overwritten this blob with its own.
WORKDIR /home
