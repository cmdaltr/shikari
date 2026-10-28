#!/bin/sh
# Install or upgrade the Archer desktop app on macOS or Linux from a GitHub release (desktop/README.md).
#
#   sh install.sh                    the latest release
#   sh install.sh --version v2.1.0   a given release
#   sh install.sh --file Archer.dmg  an installer already downloaded (no checksum: you chose the file)
#
# The repository is private: set GH_TOKEN (or GITHUB_TOKEN) to a token that can read it, or be
# logged in to the gh CLI. The installer is checked against the release's SHA256SUMS before use.
set -eu

REPO="${ARCHER_REPO:-cmdaltr/archer}"
version=latest
file=

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a tag}"; shift 2 ;;
        --file) file="${2:?--file needs a path}"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) suffix=-macos-arm64.dmg ;;
    Darwin-x86_64) suffix=-macos-x86_64.dmg ;;
    Linux-x86_64) suffix=_amd64.deb ;;
    Linux-aarch64) suffix=_arm64.deb ;;
    *) die "no Archer build for $(uname -s) $(uname -m)" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Picks a field out of the release JSON on stdin. macOS has no python3 without the developer
# tools, but always has JavaScript for Automation; Debian and Ubuntu always have python3.
# Prints "<name>\t<api url>" per asset.
assets() {
    if [ "$(uname -s)" = Darwin ]; then
        osascript -l JavaScript -e 'function run(argv) {
            var r = JSON.parse($.NSString.alloc.initWithDataEncoding($.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile, $.NSUTF8StringEncoding).js);
            if (!r.assets) throw new Error(r.message || "no release");
            return r.assets.map(function (a) { return a.name + "\t" + a.url; }).join("\n");
        }'
    else
        python3 -c 'import json, sys
r = json.load(sys.stdin)
if "assets" not in r: sys.exit(r.get("message", "no release"))
print("\n".join(a["name"] + "\t" + a["url"] for a in r["assets"]))'
    fi
}

if [ -z "$file" ]; then
    token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    if [ -z "$token" ] && command -v gh >/dev/null 2>&1; then
        token=$(gh auth token 2>/dev/null || true)
    fi
    [ -n "$token" ] || die "set GH_TOKEN to a token that can read $REPO, or log in with gh auth login"
    get() { curl -fsSL -H "Authorization: Bearer $token" "$@"; }

    [ "$version" = latest ] && path=releases/latest || path="releases/tags/$version"
    get -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$path" > "$tmp/release.json" \
        || die "couldn't read $version from $REPO"
    assets < "$tmp/release.json" > "$tmp/assets" || die "couldn't read the release's assets"

    name=$(awk -F '\t' -v s="$suffix" 'substr($1, length($1) - length(s) + 1) == s { print $1; exit }' "$tmp/assets")
    [ -n "$name" ] || die "the $version release has no *$suffix"
    url() { awk -F '\t' -v n="$1" '$1 == n { print $2; exit }' "$tmp/assets"; }
    [ -n "$(url SHA256SUMS)" ] || die "the $version release has no SHA256SUMS"

    echo "Downloading $name"
    get -H "Accept: application/octet-stream" -o "$tmp/$name" "$(url "$name")"
    get -H "Accept: application/octet-stream" -o "$tmp/SHA256SUMS" "$(url SHA256SUMS)"
    expected=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$tmp/SHA256SUMS")
    actual=$(shasum -a 256 "$tmp/$name" 2>/dev/null || sha256sum "$tmp/$name")
    [ -n "$expected" ] && [ "${actual%% *}" = "$expected" ] || die "$name doesn't match SHA256SUMS: not installing it"
    file="$tmp/$name"
fi
[ -f "$file" ] || die "no such file: $file"

case "$suffix" in
    *.dmg)
        mnt="$tmp/mnt"
        mkdir -p "$mnt"
        hdiutil attach -nobrowse -quiet -mountpoint "$mnt" "$file"
        # /Applications needs an admin account; anyone else gets their own Applications folder
        dest=/Applications
        [ -w "$dest" ] || { dest="$HOME/Applications"; mkdir -p "$dest"; }
        pgrep -xq Archer && echo "Archer is running: quit it to use the new version"
        rm -rf "$dest/Archer.app"
        ditto "$mnt/Archer.app" "$dest/Archer.app"
        hdiutil detach -quiet "$mnt"
        echo "Installed $dest/Archer.app"
        ;;
    *.deb)
        case "$file" in /*) ;; *) file="$PWD/$file" ;; esac
        # apt rather than dpkg, so GTK and WebKit come with it
        sudo=""
        [ "$(id -u)" -eq 0 ] || sudo=sudo
        $sudo apt-get install -y "$file"
        echo "Installed: run archer, or open Archer from the applications menu"
        ;;
esac
