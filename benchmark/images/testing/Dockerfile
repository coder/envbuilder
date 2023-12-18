# Use the ubuntu base image
FROM ubuntu:latest

# Set the working directory
WORKDIR /data

# Run a shell command to create 1 million 1KB files with random data in parallel and show progress
RUN seq 1 10000 | xargs -I {} -P 128 sh -c 'dd if=/dev/urandom of=file{} bs=1024 count=1 2>/dev/null; if [ $(({} % 100)) -eq 0 ]; then echo "Created {} files"; fi'
