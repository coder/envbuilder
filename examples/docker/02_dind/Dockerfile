FROM ubuntu:noble
RUN apt-get update && \
  apt-get install -y curl apt-transport-https && \
  curl -fsSL https://get.docker.com/ | sh -s -
ADD entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]