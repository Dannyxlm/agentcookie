#!/usr/bin/env bash
#
# teammate-install.sh - Install the agentcookie Linux binary for a teammate
# agent into ~/.local/bin, pinned to one release tag and one SHA256.
#
# Usage:
#   teammate-install.sh <tag> <sha256>
#
# The laptop pins both values into the pairing notice. The SHA256 is the
# one the laptop computed from the release asset, so this script never
# trusts a checksum fetched from the same place as the binary (no
# checksums.txt). Unpinned refs such as latest or main are refused.
#
# The asset is agentcookie_<version>_linux_<arch>.tar.gz from the GitHub
# release for <tag>. The binary is replaced atomically (same-directory
# rename), so an agent never runs a half-written file.
#
# Environment (for tests and mirrors):
#   AGENTCOOKIE_RELEASE_BASE_URL  default https://github.com/mvanhorn/agentcookie/releases/download
#   AGENTCOOKIE_INSTALL_DIR       default $HOME/.local/bin

set -euo pipefail

# teammate_valid_tag TAG: a pinned release tag like v1.2.3 or v1.2.3-beta.1.
teammate_valid_tag() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]
}

# teammate_valid_sha256 HEX: exactly 64 hex characters.
teammate_valid_sha256() {
  [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]
}

# teammate_linux_arch MACHINE: map `uname -m` to the release arch token.
teammate_linux_arch() {
  case "$1" in
    x86_64 | amd64) printf 'amd64\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    *)
      echo "teammate-install.sh: unsupported architecture: $1" >&2
      return 1
      ;;
  esac
}

# teammate_asset_name TAG ARCH
teammate_asset_name() {
  printf 'agentcookie_%s_linux_%s.tar.gz\n' "${1#v}" "$2"
}

teammate_sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

teammate_install() {
  local tag="${1:-}" want="${2:-}"
  if [[ -z "$tag" || -z "$want" ]]; then
    echo "usage: teammate-install.sh <tag> <sha256>" >&2
    return 2
  fi
  if ! teammate_valid_tag "$tag"; then
    echo "teammate-install.sh: refusing unpinned or invalid release ref '$tag' (need an exact tag like v1.2.3)" >&2
    return 2
  fi
  if ! teammate_valid_sha256 "$want"; then
    echo "teammate-install.sh: the second argument must be the asset's 64-character SHA256" >&2
    return 2
  fi
  want="$(printf '%s' "$want" | tr 'A-F' 'a-f')"

  local arch asset base dest work got bin
  arch="$(teammate_linux_arch "$(uname -m)")" || return 2
  asset="$(teammate_asset_name "$tag" "$arch")"
  base="${AGENTCOOKIE_RELEASE_BASE_URL:-https://github.com/mvanhorn/agentcookie/releases/download}"
  dest="${AGENTCOOKIE_INSTALL_DIR:-$HOME/.local/bin}"

  work="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'; trap - RETURN" RETURN

  if ! curl -fsSL "$base/$tag/$asset" -o "$work/$asset"; then
    echo "teammate-install.sh: download failed: $base/$tag/$asset" >&2
    return 3
  fi
  got="$(teammate_sha256_of "$work/$asset")"
  if [[ "$got" != "$want" ]]; then
    echo "teammate-install.sh: SHA256 mismatch for $asset: got $got, pinned $want; not installing" >&2
    return 4
  fi

  mkdir -p "$work/x"
  tar -xzf "$work/$asset" -C "$work/x"
  bin="$(find "$work/x" -type f -name agentcookie | head -n 1)"
  if [[ -z "$bin" ]]; then
    echo "teammate-install.sh: $asset has no agentcookie binary" >&2
    return 4
  fi

  mkdir -p "$dest"
  cp "$bin" "$dest/.agentcookie.new.$$"
  chmod 0755 "$dest/.agentcookie.new.$$"
  mv -f "$dest/.agentcookie.new.$$" "$dest/agentcookie"
  echo "teammate-install.sh: installed agentcookie $tag to $dest/agentcookie"
}

if [[ "${AGENTCOOKIE_TEAMMATE_INSTALL_LIB_ONLY:-}" == "1" ]]; then
  if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
  fi
  exit 0
fi

teammate_install "$@"
