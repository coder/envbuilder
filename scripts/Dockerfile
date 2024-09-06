FROM scratch
ARG TARGETARCH

COPY envbuilder-${TARGETARCH} /.envbuilder/bin/envbuilder

ENV KANIKO_DIR /.envbuilder

ENTRYPOINT ["/.envbuilder/bin/envbuilder"]
