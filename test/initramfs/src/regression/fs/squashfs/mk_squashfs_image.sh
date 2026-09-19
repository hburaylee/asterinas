#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

IMAGE_PATH="$1"
STAGING_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING_DIR"' EXIT

LONG_NAME="$(printf 'long_filename_%0200d.txt' 0)"

# Small file
printf 'hello squashfs\n' > "$STAGING_DIR/small.txt"

# Empty file
touch "$STAGING_DIR/empty.txt"

# Exact block-size file (4096 bytes of 'A')
dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'A' > "$STAGING_DIR/exact_block.bin"

# Large file (128KB, each byte = offset % 256)
python3 -c "import sys; sys.stdout.buffer.write(bytes([i%256 for i in range(131072)]))" > "$STAGING_DIR/large.bin"

# Fragment file
printf 'fragment_test\n' > "$STAGING_DIR/fragment.txt"

# Symlink
ln -s small.txt "$STAGING_DIR/link.txt"

# Deep directory (8 levels)
mkdir -p "$STAGING_DIR/a/b/c/d/e/f/g/h"
printf 'deep file\n' > "$STAGING_DIR/a/b/c/d/e/f/g/h/deep.txt"

# Long target symlink (> 60 chars to trigger extended symlink)
ln -s a/b/c/d/e/f/g/h/deep.txt "$STAGING_DIR/long_target_link"

# Many entries directory (200 files)
mkdir -p "$STAGING_DIR/many_entries"
for i in $(seq -w 0 199); do touch "$STAGING_DIR/many_entries/file_$i"; done

# Long filename (255 bytes)
touch "$STAGING_DIR/$LONG_NAME"

# Permission variants
mkdir -p "$STAGING_DIR/permissions"
touch "$STAGING_DIR/permissions/readonly.txt"
chmod 0444 "$STAGING_DIR/permissions/readonly.txt"
touch "$STAGING_DIR/permissions/executable.sh"
chmod 0755 "$STAGING_DIR/permissions/executable.sh"
touch "$STAGING_DIR/permissions/noperm.txt"
chmod 0000 "$STAGING_DIR/permissions/noperm.txt"

# Mixed types directory
mkdir -p "$STAGING_DIR/mixed_types/subdir"
printf 'regular\n' > "$STAGING_DIR/mixed_types/regular.txt"
ln -s regular.txt "$STAGING_DIR/mixed_types/symlink"

# TODO: install mksquashfs in Dockerfile
apt update
apt install -y squashfs-tools

mksquashfs "$STAGING_DIR" "$IMAGE_PATH" -noappend -comp zstd
