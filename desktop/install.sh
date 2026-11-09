#!/bin/sh
# Install or upgrade the Shikari desktop app on macOS or Linux from a GitHub release (desktop/README.md).
#
#   sh install.sh                    the latest release
#   sh install.sh --version v2.1.0   a given release
#   sh install.sh --file Shikari.dmg  an installer already downloaded (no checksum: you chose the file)
#   sh install.sh --launch           open Shikari when it's installed
#   sh install.sh --clean            a clean install: once the new installer is downloaded and checked,
#                                    remove the current app and its data folder (uninstall.sh --yes) first
#
# The repository is private: set GH_TOKEN (or GITHUB_TOKEN) to a token that can read it, or be
# logged in to the gh CLI. The installer is checked against the release's SHA256SUMS before use.
set -eu

REPO="${SHIKARI_REPO:-cmdaltr/shikari}"
version=latest
file=
launch=
clean=
started=$(date +%s)

# Numbered steps, so it's clear how far through the install is. Colour only on a terminal.
if [ -t 1 ]; then c=$(printf '\033[36m'); g=$(printf '\033[32m'); d=$(printf '\033[2m'); r=$(printf '\033[31m'); o=$(printf '\033[0m')
else c= g= d= r= o=; fi
n=0
steps=0
step() { n=$((n + 1)); printf '\n%s[%d/%d] %s%s\n' "$c" "$n" "$steps" "$*" "$o"; }
ok() { printf '      %sOK  %s%s\n' "$g" "$*" "$o"; }
note() { printf '      %s%s%s\n' "$d" "$*" "$o"; }
die() { printf '\n%sinstall.sh: %s%s\n' "$r" "$*" "$o" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a tag}"; shift 2 ;;
        --file) file="${2:?--file needs a path}"; shift 2 ;;
        --launch) launch=1; shift ;;
        --clean) clean=1; shift ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) suffix=-macos-arm64.dmg ;;
    Darwin-x86_64) suffix=-macos-x86_64.dmg ;;
    Linux-x86_64) suffix=_amd64.deb ;;
    Linux-aarch64) suffix=_arm64.deb ;;
    *) die "no Shikari build for $(uname -s) $(uname -m)" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --clean runs the uninstaller beside this script (the repository's desktop/, or the installed app's
# seed/). Copied out first: it deletes the app this script may be running from
if [ -n "$clean" ]; then
    [ -f "$(dirname "$0")/uninstall.sh" ] || die "--clean needs uninstall.sh beside install.sh (the app's seed folder, or the repository's desktop folder)"
    cp "$(dirname "$0")/uninstall.sh" "$tmp/uninstall.sh"
fi

# Find, download and check the installer when there's no --file, (clean,) install it, done
[ -n "$file" ] && steps=1 || steps=4
[ -n "$clean" ] && steps=$((steps + 1))
printf '\n  Shikari: desktop app installer\n'
printf '  %sshi\302\267ka\302\267ri  \\shi-\313\210k\303\244r-\304\223\\  a professional big-game hunter or guide%s\n' "$d" "$o"

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

    step "Finding the $version release of $REPO"
    [ "$version" = latest ] && path=releases/latest || path="releases/tags/$version"
    get -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$path" > "$tmp/release.json" \
        || die "couldn't read $version from $REPO"
    assets < "$tmp/release.json" > "$tmp/assets" || die "couldn't read the release's assets"

    name=$(awk -F '\t' -v s="$suffix" 'substr($1, length($1) - length(s) + 1) == s { print $1; exit }' "$tmp/assets")
    [ -n "$name" ] || die "the $version release has no *$suffix"
    url() { awk -F '\t' -v n="$1" '$1 == n { print $2; exit }' "$tmp/assets"; }
    [ -n "$(url SHA256SUMS)" ] || die "the $version release has no SHA256SUMS"
    ok "$name"

    step "Downloading $name"
    # curl's own bar on a terminal (get's -s would hide it); quiet in a log
    if [ -t 2 ]; then
        curl -fL -# -H "Authorization: Bearer $token" -H "Accept: application/octet-stream" -o "$tmp/$name" "$(url "$name")"
    else
        get -H "Accept: application/octet-stream" -o "$tmp/$name" "$(url "$name")"
    fi
    get -H "Accept: application/octet-stream" -o "$tmp/SHA256SUMS" "$(url SHA256SUMS)"
    ok "$(du -h "$tmp/$name" | cut -f1 | tr -d ' ') downloaded"

    step "Checking it against the release's SHA256SUMS"
    expected=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$tmp/SHA256SUMS")
    actual=$(shasum -a 256 "$tmp/$name" 2>/dev/null || sha256sum "$tmp/$name")
    [ -n "$expected" ] && [ "${actual%% *}" = "$expected" ] || die "$name doesn't match SHA256SUMS: not installing it"
    ok "SHA-256 matches"
    file="$tmp/$name"
fi
[ -f "$file" ] || die "no such file: $file"
case "$file" in /*) ;; *) file="$PWD/$file" ;; esac

if [ -n "$clean" ]; then
    step "Removing the current install and its data folder"
    sh "$tmp/uninstall.sh" --yes < /dev/null | grep '^      ' || true
fi

step "Installing $(basename "$file")"

case "$suffix" in
    *.dmg)
        mnt="$tmp/mnt"
        mkdir -p "$mnt"
        note "Opening the disk image"
        hdiutil attach -nobrowse -quiet -mountpoint "$mnt" "$file"
        # /Applications needs an admin account; anyone else gets their own Applications folder
        dest=/Applications
        [ -w "$dest" ] || { dest="$HOME/Applications"; mkdir -p "$dest"; }
        pgrep -xq Shikari && note "Shikari is running: quit it to use the new version"
        note "Copying Shikari.app to $dest"
        rm -rf "$dest/Shikari.app"
        ditto "$mnt/Shikari.app" "$dest/Shikari.app"
        hdiutil detach -quiet "$mnt"
        ok "$dest/Shikari.app"
        where="Open it from Launchpad or $dest"
        ;;
    *.deb)
        # apt rather than dpkg, so GTK and WebKit come with it
        sudo=""
        if [ "$(id -u)" -ne 0 ]; then
            sudo=sudo
            note "apt needs administrator rights: sudo may ask for your password"
            sudo true || die "no administrator rights"
        fi
        # apt's own output is hundreds of lines (every GTK and WebKit package): keep it in a log, show a
        # clock so it doesn't look stuck, and print the end of the log if it fails
        note "apt is installing it with GTK and WebKit (a few minutes on a fresh machine)"
        $sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$file" > "$tmp/apt.log" 2>&1 &
        pid=$!
        t=0
        while kill -0 "$pid" 2>/dev/null; do
            [ -t 1 ] && printf '\r      %s%dm %02ds%s' "$d" $((t / 60)) $((t % 60)) "$o"
            sleep 1
            t=$((t + 1))
        done
        [ -t 1 ] && printf '\r              \r'
        if ! wait "$pid"; then
            tail -n 25 "$tmp/apt.log" >&2
            die "apt couldn't install $(basename "$file")"
        fi
        ok "Installed, with $(grep -c '^Setting up' "$tmp/apt.log") package(s)"
        where="Run shikari, or open Shikari from the applications menu"
        ;;
esac

took=$(( $(date +%s) - started ))
printf '\n  %sShikari is installed (%dm %ds). %s.%s\n' "$g" $((took / 60)) $((took % 60)) "$where" "$o"
printf '  %sThe first start takes a few minutes while it unpacks MITRE ATT&CK; after that, seconds.%s\n' "$d" "$o"
if [ -n "$launch" ]; then
    case "$suffix" in *.dmg) open "$dest/Shikari.app" ;; *) (shikari >/dev/null 2>&1 &) ;; esac
fi
