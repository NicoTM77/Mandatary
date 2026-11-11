#!/usr/bin/env bash
# Isolated, checksum-verified developer toolchains; never a global install.
set -euo pipefail
version=${MANDATARY_GO_VERSION:-1.27.4}
case "$version" in
  1.27.4|1.26.11) ;;
  *) printf 'UNAPPROVED_GO_VERSION: %s\n' "$version" >&2; exit 1 ;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
case "$(uname -s)" in
  Linux) os=linux; node_ext=tar.xz ;;
  Darwin) os=darwin; node_ext=tar.gz ;;
  *) printf 'Unsupported developer OS\n' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) arch=amd64; node_arch=x64 ;;
  aarch64|arm64) arch=arm64; node_arch=arm64 ;;
  *) printf 'Unsupported developer CPU\n' >&2; exit 1 ;;
esac
dest=${MANDATARY_TOOLCHAIN_DIR:-$root/.toolchains}
mkdir -p "$dest"
stage=$(mktemp -d "$dest/.bootstrap.XXXXXX")
trap 'rm -rf "$stage"' EXIT
verify() {
  local filename=$1 expected='' digest name actual
  while read -r digest name; do
    if [[ $name == "$filename" ]]; then expected=$digest; break; fi
  done < "$root/scripts/toolchains.sha256"
  [[ -n $expected ]] || { printf 'Missing checksum: %s\n' "$filename" >&2; return 1; }
  if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$stage/$filename")
  else
    actual=$(shasum -a 256 "$stage/$filename")
  fi
  [[ ${actual%% *} == "$expected" ]] || { printf 'Checksum mismatch: %s\n' "$filename" >&2; return 1; }
}
install_archive() {
  local filename=$1 url=$2 target=$3
  if [[ -e $dest/$target ]]; then return; fi
  curl --fail --location --proto '=https' --tlsv1.2 --output "$stage/$filename" "$url"
  verify "$filename"
  mkdir "$stage/unpack"
  tar -xf "$stage/$filename" -C "$stage/unpack" --strip-components=1
  mv "$stage/unpack" "$dest/$target"
}
go_file="go$version.$os-$arch.tar.gz"
node_file="node-v24.22.1-$os-$node_arch.$node_ext"
install_archive "$go_file" "https://go.dev/dl/$go_file" "go$version"
install_archive "$node_file" "https://nodejs.org/dist/v24.22.1/$node_file" node24.22.1
PATH="$dest/go$version/bin:$dest/node24.22.1/bin:$PATH" bash "$root/scripts/check-toolchains.sh"
printf '\nToolchains ready. Add these directories to PATH:\n%s\n%s\n' "$dest/go$version/bin" "$dest/node24.22.1/bin"
