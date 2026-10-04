#!/usr/bin/env bash
# Install the web3-crawler CLI.
#
#   curl -fsSL https://raw.githubusercontent.com/hems06/web3-crawler/main/install.sh | bash
#   ./install.sh                # from a clone
#
# Options (environment variables):
#   WEB3_CRAWLER_HOME   install directory      (default: ~/.web3-crawler)
#   WEB3_CRAWLER_REF    git branch or tag      (default: main)
#   WEB3_CRAWLER_BIN    where to link `crawler` (default: ~/.local/bin)
#   WITH_DASHBOARD=1    also install the React dashboard (needs Node 20+)
#   WITH_KEYRING=1      store the SMTP password in the OS keyring
set -euo pipefail

REPO_URL="https://github.com/hems06/web3-crawler.git"
HOME_DIR="${WEB3_CRAWLER_HOME:-$HOME/.web3-crawler}"
REF="${WEB3_CRAWLER_REF:-main}"
BIN_DIR="${WEB3_CRAWLER_BIN:-$HOME/.local/bin}"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Pick a Python 3.11+ interpreter.
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PYTHON="$candidate"; break
  fi
done
[ -n "$PYTHON" ] || die "Python 3.11 or newer is required"
command -v git >/dev/null 2>&1 || die "git is required"

# Use the current clone when run from inside it, otherwise clone or update.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/pyproject.toml" ] && [ -d "$SCRIPT_DIR/crawler" ]; then
  SRC="$SCRIPT_DIR"
  say "Installing from $SRC"
else
  SRC="$HOME_DIR/src"
  if [ -d "$SRC/.git" ]; then
    say "Updating $SRC ($REF)"
    git -C "$SRC" fetch --quiet origin "$REF"
    git -C "$SRC" checkout --quiet "$REF"
    git -C "$SRC" pull --quiet --ff-only origin "$REF"
  else
    say "Cloning $REPO_URL ($REF) into $SRC"
    mkdir -p "$HOME_DIR"
    git clone --quiet --branch "$REF" "$REPO_URL" "$SRC"
  fi
fi

VENV="$HOME_DIR/venv"
say "Creating virtual environment in $VENV"
mkdir -p "$HOME_DIR"
"$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
EXTRAS="dev"
[ "${WITH_KEYRING:-0}" = "1" ] && EXTRAS="$EXTRAS,keyring"
say "Installing web3-crawler[$EXTRAS]"
"$VENV/bin/python" -m pip install --quiet -e "$SRC[$EXTRAS]"

# Settings and data live next to the source so `crawler` finds them.
if [ ! -f "$SRC/.env" ]; then
  cp "$SRC/.env.example" "$SRC/.env"
  sed -i.bak "s#^DATABASE_URL=.*#DATABASE_URL=sqlite:///$HOME_DIR/data/crawler.db#" "$SRC/.env" && rm -f "$SRC/.env.bak"
  say "Created $SRC/.env (the first crawler run asks for your name, SMTP and OpenAI key)"
fi
mkdir -p "$HOME_DIR/data"

# Link the CLI onto PATH. It reads $SRC/.env from any directory.
mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/crawler" "$BIN_DIR/crawler"

if [ "${WITH_DASHBOARD:-0}" = "1" ]; then
  command -v npm >/dev/null 2>&1 || die "WITH_DASHBOARD=1 needs Node.js and npm"
  say "Installing dashboard dependencies"
  (cd "$SRC/dashboard" && npm ci --silent)
fi

say "Checking the install"
"$BIN_DIR/crawler" --help >/dev/null

say "Installed. Try: crawler"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "    Add $BIN_DIR to your PATH, e.g.: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc" ;;
esac
