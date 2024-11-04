FROM ubuntu:noble

# Based on UID of ubuntu user in container.
ENV XDG_RUNTIME_DIR /run/user/1000
ENV DOCKER_HOST unix:///${XDG_RUNTIME_DIR}/docker.sock

# Setup as root
USER root
RUN apt-get update && \
  # Install prerequisites
  apt-get install -y apt-transport-https curl iproute2 uidmap && \
  # Install Docker
  curl -fsSL https://get.docker.com/ | sh -s - && \
  # Add ubuntu user to docker group
  usermod -aG docker ubuntu && \
  # Create the XDG_RUNTIME_DIR for our user and set DOCKER_HOST
  mkdir -p ${XDG_RUNTIME_DIR} && \ 
  chown ubuntu:ubuntu ${XDG_RUNTIME_DIR}

# Setup rootless mode as the ubuntu user.
USER ubuntu
RUN dockerd-rootless-setuptool.sh install && \
  docker context use rootless && \
  mkdir -p /home/ubuntu/.local/share/docker

# Add our onCreateCommand script.
ADD on-create.sh /on-create.sh

ENTRYPOINT ["bash"]