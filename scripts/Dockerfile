FROM scratch

COPY envbuilder /envbuilder/bin/envbuilder

ENV KANIKO_DIR /envbuilder
ENV DOCKER_CONFIG /envbuilder

ENTRYPOINT ["/envbuilder/bin/envbuilder"]
