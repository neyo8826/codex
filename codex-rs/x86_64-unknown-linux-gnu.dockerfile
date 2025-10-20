FROM ubuntu:jammy AS cross-base

RUN export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install --assume-yes --no-install-recommends \
    g++-x86-64-linux-gnu \
    libc6-dev-amd64-cross \
    libssl-dev \
    pkg-config
