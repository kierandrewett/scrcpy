#!/bin/sh
# Build scrcpy-server-linux-aarch64: the native scrcpy server for postmarketOS.
#
# The result is a fully static musl aarch64 executable, so it runs on a
# postmarketOS device without any extra packages installed. It is built inside
# an x86_64 Alpine container that cross-compiles with clang/lld against an
# aarch64 Alpine sysroot. wayland-client and x264 are built from pinned source
# tarballs, so the result does not rely on Alpine's LTO-built libraries.
#
# Usage: server-linux/build-static.sh [OUTPUT_DIR]
#   OUTPUT_DIR defaults to server-linux/out.
#   CONTAINER_RUNTIME (default: podman) may be set to docker.
#   ALPINE_IMAGE (default: docker.io/library/alpine:3.22) may be overridden.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/out}
runtime=${CONTAINER_RUNTIME:-podman}
image=${ALPINE_IMAGE:-docker.io/library/alpine:3.22}

mkdir -p "$out"
out=$(cd "$out" && pwd)

# Pinned to amd64: the build host runs x86_64 and the aarch64 target is only
# cross-compiled, never executed, so no qemu/binfmt is needed.
# :z relabels the mounts for SELinux hosts (Fedora); it is a no-op elsewhere.
exec "$runtime" run --rm --platform linux/amd64 \
    -v "$here:/src:ro,z" \
    -v "$out:/out:z" \
    "$image" \
    sh /src/container-build.sh
