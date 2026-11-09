#!/bin/sh
# Remove the Shikari desktop app from macOS or Linux (desktop/README.md).
#
#   sh uninstall.sh              remove the app, then ask before deleting its data folder
#   sh uninstall.sh --keep-data  remove the app only: the data folder stays for a reinstall
#   sh uninstall.sh --yes        don't ask: delete the data folder too
#
# The data folder is SHIKARI_HOME: the database, generated detections, bespoke/ and logs. Without
# a terminal to ask on, it's kept unless --yes says otherwise. On macOS a Shikari checkout's own
# server (the `shikari` command in a repository) keeps its files in the same Application Support
# folder, and its logs in ~/Library/Logs/Shikari: those are never touched.
set -eu

data=ask
while [ $# -gt 0 ]; do
    case "$1" in
        --keep-data) data=keep; shift ;;
        --yes|-y) data=delete; shift ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) printf 'uninstall.sh: unknown option %s\n' "$1" >&2; exit 1 ;;
    esac
done

if [ -t 1 ]; then c=$(printf '\033[36m'); g=$(printf '\033[32m'); d=$(printf '\033[2m'); r=$(printf '\033[31m'); o=$(printf '\033[0m')
else c= g= d= r= o=; fi
n=0
steps=3
step() { n=$((n + 1)); printf '\n%s[%d/%d] %s%s\n' "$c" "$n" "$steps" "$*" "$o"; }
ok() { printf '      %sOK  %s%s\n' "$g" "$*" "$o"; }
note() { printf '      %s%s%s\n' "$d" "$*" "$o"; }
die() { printf '\n%suninstall.sh: %s%s\n' "$r" "$*" "$o" >&2; exit 1; }

case "$(uname -s)" in
    Darwin)
        os=mac
        base="$HOME/Library/Application Support/Shikari"
        ;;
    Linux)
        os=linux
        base="${XDG_DATA_HOME:-$HOME/.local/share}/shikari"
        ;;
    *) die "no Shikari desktop app for $(uname -s)" ;;
esac
home="${SHIKARI_HOME:-$base/home}"

printf '\n  Shikari: desktop app uninstaller\n'

step "Quitting Shikari"
if [ $os = mac ]; then
    if pgrep -xq Shikari; then osascript -e 'quit app "Shikari"' >/dev/null 2>&1 || true; sleep 2; pkill -x Shikari || true; ok "Quit"
    else ok "Not running"; fi
else
    if pgrep -f '^/usr/lib/shikari/' >/dev/null; then pkill -f '^/usr/lib/shikari/' || true; sleep 1; ok "Quit"
    else ok "Not running"; fi
fi

step "Removing the app"
if [ $os = mac ]; then
    removed=
    for app in /Applications/Shikari.app "$HOME/Applications/Shikari.app"; do
        [ -d "$app" ] || continue
        if [ -w "$(dirname "$app")" ]; then rm -rf "$app"
        else note "$(dirname "$app") needs administrator rights: sudo may ask for your password"; sudo rm -rf "$app"; fi
        ok "$app"
        removed=1
    done
    [ -n "$removed" ] || ok "No Shikari.app in /Applications or ~/Applications"
    # What macOS keeps per app outside the data folder: WKWebView ignores the app's storage path
    for f in "$HOME/Library/Caches/com.cmdaltr.shikari" "$HOME/Library/WebKit/com.cmdaltr.shikari" \
             "$HOME/Library/HTTPStorages/com.cmdaltr.shikari" "$HOME/Library/HTTPStorages/com.cmdaltr.shikari".binarycookies* \
             "$HOME/Library/Preferences/com.cmdaltr.shikari.plist" \
             "$HOME/Library/Saved Application State/com.cmdaltr.shikari.savedState"; do
        [ -e "$f" ] || continue
        rm -rf "$f"
        note "Removed $f"
    done
else
    if dpkg -s shikari >/dev/null 2>&1; then
        sudo=""
        if [ "$(id -u)" -ne 0 ]; then
            sudo=sudo
            note "apt needs administrator rights: sudo may ask for your password"
        fi
        $sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq shikari >/dev/null || die "apt couldn't remove shikari"
        ok "shikari package purged"
        note "GTK and WebKit stay: other apps use them (sudo apt autoremove clears what nothing needs)"
    else
        ok "The shikari package isn't installed"
    fi
fi

step "The data folder"
if [ ! -d "$home" ]; then
    ok "None at $home"
else
    size=$(du -sh "$home" 2>/dev/null | cut -f1 | tr -d ' ')
    if [ $data = ask ]; then
        if [ -t 0 ]; then
            printf '      Delete %s (%s): the database, detections and bespoke/? It can'\''t be undone. [y/N] ' "$home" "$size"
            read -r answer
            case "$answer" in [yY]*) data=delete ;; *) data=keep ;; esac
        else
            data=keep
        fi
    fi
    if [ $data = delete ]; then
        rm -rf "$home"
        # The parent goes too once it's empty; on macOS it also holds a checkout's server files, then it stays
        [ -z "${SHIKARI_HOME:-}" ] && rmdir "$base" 2>/dev/null || true
        ok "Deleted $home ($size)"
    else
        ok "Kept $home ($size): delete it to start again, or reinstall to carry on"
    fi
fi

printf '\n  %sShikari is uninstalled.%s\n' "$g" "$o"
