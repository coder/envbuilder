FROM scratch
ARG TARGETARCH

COPY envbuilder-${TARGETARCH} /.envbuilder/bin/envbuilder

ENV KANIKO_DIR /.envbuilder
# Kaniko looks for the Docker config at $DOCKER_CONFIG/config.json
ENV DOCKER_CONFIG /.envbuilder

ENTRYPOINT ["/.envbuilder/bin/envbuilder"]
