FROM ubuntu:noble

# Install Docker using Docker's convenience script.
RUN apt-get update && \
    apt-get install -y curl sudo apt-transport-https && \
    curl -fsSL https://get.docker.com/ | sh -s -

# The ubuntu:noble image includes a non-root user by default,
# but it does not have sudo privileges. We need to set this up.
# Note: we chown /var/run/docker.sock to the non-root user
# in the onCreateCommand script. Ideally you would add the
# non-root user to the docker group, but in this scenario
# this is a 'single-user' environment. It also avoids us
# having to run `newgrp docker`.
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu

# Add our onCreateCommand script.
ADD on-create.sh /on-create.sh

# Switch to the non-root user.
USER ubuntu

ENTRYPOINT ["bash"]
