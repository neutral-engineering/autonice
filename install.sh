#!/bin/sh
# autonice installer — download the static release binary, verify its SHA-256,
# and run `autonice install` (which self-installs the systemd service).
#
#   curl -fsSL https://raw.githubusercontent.com/neutral-engineering/autonice/main/install.sh | sh
#
# It is deliberately small and POSIX, and it PRINTS EVERY STEP so you can see
# exactly what it does to your system before it does it. Overrides (env vars):
#   AUTONICE_VERSION   release tag to install     (default: latest)
#   AUTONICE_BASE_URL  where to fetch the assets  (default: GitHub releases)
set -eu

REPO="neutral-engineering/autonice"
VERSION="${AUTONICE_VERSION:-latest}"
if [ "$VERSION" = "latest" ]; then
  BASE="${AUTONICE_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
else
  BASE="${AUTONICE_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
fi

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }

say "autonice installer — fetch a static binary, verify its checksum, then install a systemd service."

# 1. The released binary is a static x86_64 musl build — refuse anything else.
os="$(uname -s)"; arch="$(uname -m)"
[ "$os" = "Linux" ] || { echo "autonice: only Linux is supported (got $os)" >&2; exit 1; }
case "$arch" in
  x86_64|amd64) ;;
  *) echo "autonice: only x86_64 is supported (got $arch)" >&2; exit 1 ;;
esac

# 2. Tools: a downloader, sha256sum, and root (via sudo if we're not root).
if command -v curl >/dev/null 2>&1; then DL="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then DL="wget -qO"
else echo "autonice: need curl or wget" >&2; exit 1; fi
command -v sha256sum >/dev/null 2>&1 || { echo "autonice: need sha256sum" >&2; exit 1; }
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 3. Download the binary + its checksum.
say "Downloading from $BASE"
say "  $BASE/autonice"
$DL "$tmp/autonice" "$BASE/autonice"
say "  $BASE/autonice.sha256"
$DL "$tmp/autonice.sha256" "$BASE/autonice.sha256"

# 4. Verify — abort on mismatch (set -e) so a bad download never gets installed.
say "Verifying SHA-256"
( cd "$tmp" && sha256sum -c autonice.sha256 )
chmod +x "$tmp/autonice"

# 5. Self-install. `autonice install` copies the (just-downloaded) binary to
#    /usr/local/bin, writes the unit + /etc/autonice.toml (kept if it exists),
#    and enables the service. Needs root.
say "Installing the systemd service with: $SUDO $tmp/autonice install"
say "  this copies autonice to /usr/local/bin, writes /etc/autonice.toml + the unit, and enables it"
$SUDO "$tmp/autonice" install

say "Done.  status: systemctl status autonice   logs: journalctl -u autonice -f"
