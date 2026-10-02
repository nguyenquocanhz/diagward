#!/bin/sh
# Install Diagward on Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/nguyenquocanhz/diagward/main/install.sh | sh
#
# Downloads the static binary for this CPU from the latest GitHub release,
# verifies its SHA-256 checksum, and installs it to /usr/local/bin (as root)
# or ~/.local/bin. Set DIAGWARD_VERSION=0.1.0 to pin a version.
set -eu

repo="nguyenquocanhz/diagward"

say() { printf '%s\n' "$*" >&2; }
die() { say "diagward install: $*"; exit 1; }

[ "$(uname -s)" = Linux ] || die "this installer is for Linux; download Windows builds from https://github.com/$repo/releases"

case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "no build for $(uname -m) yet" ;;
esac

if [ -n "${DIAGWARD_VERSION:-}" ]; then
	base="https://github.com/$repo/releases/download/v${DIAGWARD_VERSION#v}"
else
	base="https://github.com/$repo/releases/latest/download"
fi

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

if command -v sha256sum >/dev/null 2>&1; then
	sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v busybox >/dev/null 2>&1; then
	sha() { busybox sha256sum "$1" | cut -d' ' -f1; }
else
	die "sha256sum is required to verify the download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

name="diagward-linux-$arch"
say "Downloading $name ..."
fetch "$base/$name" "$tmp/diagward"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"

want=$(grep " $name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
[ -n "$want" ] || die "no checksum for $name in SHA256SUMS"
got=$(sha "$tmp/diagward")
[ "$want" = "$got" ] || die "checksum mismatch for $name (expected $want, got $got)"

if [ "$(id -u)" = 0 ]; then
	dest=/usr/local/bin
else
	dest="$HOME/.local/bin"
	mkdir -p "$dest"
fi
install -m 0755 "$tmp/diagward" "$dest/diagward" 2>/dev/null || { cp "$tmp/diagward" "$dest/diagward" && chmod 0755 "$dest/diagward"; }

say "Installed $("$dest/diagward" version 2>/dev/null || echo diagward) to $dest/diagward"
case ":$PATH:" in
	*":$dest:"*) ;;
	*) say "Note: $dest is not in your PATH." ;;
esac
say "Run a check:  sudo diagward        (Vietnamese: sudo diagward --lang vi)"
