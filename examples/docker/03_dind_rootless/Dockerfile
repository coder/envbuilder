FROM ubuntu:latest
## Install prerequisites
RUN apt-get update && \
  apt-get install -y apt-transport-https curl iproute2 uidmap
# Install Docker daemon
RUN curl -fsSL https://get.docker.com/ | sh -s -
# Add the ubuntu user to the Docker group
RUN usermod -aG docker ubuntu
# Add our custom entrypoint
ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Create the XDG_RUNTIME_DIR for our user and set DOCKER_HOST
ENV XDG_RUNTIME_DIR /run/user/1000
RUN mkdir -p ${XDG_RUNTIME_DIR} && chown ubuntu:ubuntu ${XDG_RUNTIME_DIR}
ENV DOCKER_HOST unix:///${XDG_RUNTIME_DIR}/docker.sock
# Setup rootless mode as the ubuntu user.
USER ubuntu
RUN dockerd-rootless-setuptool.sh install
# Switch the ubuntu user to use the rootless docker context
RUN docker context use rootless
RUN mkdir -p /home/ubuntu/.local/share/docker
ENTRYPOINT ["/entrypoint.sh"]