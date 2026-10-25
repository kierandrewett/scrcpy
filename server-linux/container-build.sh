#!/bin/sh
# Runs inside the Alpine build container; see build-static.sh.
#
# Produces a fully static aarch64 musl binary. Every link goes through clang
# with lld and a sysroot that holds only aarch64 musl headers and libraries.
# The host ld is x86-only, so the host toolchain is clang and lld only.
set -eu

WAYLAND_VERSION=1.23.1
WAYLAND_URL=https://gitlab.freedesktop.org/wayland/wayland/-/releases/$WAYLAND_VERSION/downloads/wayland-$WAYLAND_VERSION.tar.xz
WAYLAND_SHA256=864fb2a8399e2d0ec39d56e9d9b753c093775beadc6022ce81f441929a81e5ed

# Alpine's libx264.a is built with GCC slim LTO, which lld cannot read, so
# x264 is built from source. The stable branch snapshot is pinned by SHA-256.
X264_URL=https://code.videolan.org/videolan/x264/-/archive/stable/x264-stable.tar.bz2
X264_SHA256=740126cb48549ca4e2f09b4ae13beed592d5b54744044e38f28662fd96d0ba56

TARGET=aarch64-alpine-linux-musl
SYSROOT=/sysroot
PREFIX=/opt/deps
WORK=/work
OUT_NAME=scrcpy-server-linux-aarch64

apk add --no-cache clang lld llvm binutils meson ninja pkgconf wayland-dev curl xz tar file make bash

# Target sysroot: musl libc, headers and the aarch64 gcc runtime (crtbeginT.o,
# libgcc.a). clang finds the gcc runtime inside --sysroot, so -static links
# need no host gcc. wayland-dev on the host supplies wayland-scanner. The full
# Alpine keyring in /usr/share/apk/keys trusts the aarch64 index.
mkdir -p "$SYSROOT/etc/apk"
cp /etc/apk/repositories "$SYSROOT/etc/apk/repositories"
apk --root "$SYSROOT" --arch aarch64 --keys-dir /usr/share/apk/keys --initdb --no-scripts add \
    musl-dev gcc libffi-dev wlr-protocols

mkdir -p "$WORK" "$PREFIX"
cd "$WORK"

cat > "$WORK/cross.txt" <<EOF
[binaries]
c = ['clang', '--target=$TARGET', '--sysroot=$SYSROOT']
ar = 'llvm-ar'
ranlib = 'llvm-ranlib'
strip = 'llvm-strip'
pkg-config = 'pkg-config'

[built-in options]
c_link_args = ['-fuse-ld=lld']

[host_machine]
system = 'linux'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'

[properties]
sys_root = '$SYSROOT'
pkg_config_libdir = '$SYSROOT/usr/lib/pkgconfig:$SYSROOT/usr/share/pkgconfig'
EOF

# x264: static library only, no asm (no nasm in the container), no cli.
curl -fsSL -o x264.tar.bz2 "$X264_URL"
echo "$X264_SHA256  x264.tar.bz2" | sha256sum -c -
tar -xjf x264.tar.bz2
cd "$WORK"/x264-stable
CC="clang --target=$TARGET --sysroot=$SYSROOT" \
AR=llvm-ar RANLIB=llvm-ranlib STRIP=llvm-strip \
./configure --host=$TARGET --prefix="$PREFIX" \
    --enable-static --disable-shared --disable-cli --disable-asm \
    --disable-opencl --disable-lavf --disable-ffms --disable-gpac \
    --extra-ldflags="-fuse-ld=lld"
make -j"$(nproc)"
make install-lib-static
cd "$WORK"

# Static libwayland-client for the target. The scanner is the host one.
curl -fsSL -o wayland.tar.xz "$WAYLAND_URL"
echo "$WAYLAND_SHA256  wayland.tar.xz" | sha256sum -c -
tar -xf wayland.tar.xz

meson setup "$WORK/build" "$WORK/wayland-$WAYLAND_VERSION" \
    --cross-file "$WORK/cross.txt" \
    --prefix "$PREFIX" \
    --default-library=static \
    -Dlibraries=true \
    -Dscanner=false \
    -Ddocumentation=false \
    -Dtests=false \
    -Ddtd_validation=false
ninja -C "$WORK/build"
ninja -C "$WORK/build" install
# wayland does not install its internal wayland-util archive, and meson emits
# it as a thin archive that refers to objects in the build tree. wayland-client
# needs it at link time, so rebuild a self-contained archive from the objects.
llvm-ar rcs "$PREFIX/lib/libwayland-util.a" "$WORK"/build/src/libwayland-util.a.p/*.o

# Generate the wlr-screencopy protocol glue with the host scanner.
wlr=$SYSROOT/usr/share/wlr-protocols/unstable/wlr-screencopy-unstable-v1.xml
wayland-scanner client-header "$wlr" "$WORK/wlr-screencopy-unstable-v1-client-protocol.h"
wayland-scanner private-code "$wlr" "$WORK/wlr-screencopy-unstable-v1-protocol.c"

# Static link. -s strips symbols.
clang --target=$TARGET --sysroot=$SYSROOT -fuse-ld=lld \
    -static -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
    -Wno-missing-field-initializers \
    -I"$PREFIX/include" -I"$WORK" \
    -o "/out/$OUT_NAME" \
    /src/scrcpy_server.c "$WORK/wlr-screencopy-unstable-v1-protocol.c" \
    -L"$PREFIX/lib" -Wl,--gc-sections -s \
    -lwayland-client -lwayland-util -lffi -lx264 -lpthread -lm

cd /out
file "$OUT_NAME"
if llvm-readelf -l "$OUT_NAME" | grep -q INTERP; then
    echo "error: dynamic interpreter present" >&2
    exit 1
fi
sha256sum "$OUT_NAME" > "$OUT_NAME.sha256"
cat "$OUT_NAME.sha256"
