#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="ifname"
SRC="$(cd "$(dirname "$0")" && pwd)/ifname.py"
DEST="$HOME/bin/$SCRIPT_NAME"

if [[ ! -f "$SRC" ]]; then
    echo "ERROR: ifname.py not found in $(dirname "$SRC")" >&2
    exit 1
fi

mkdir -p "$HOME/bin"
install -m 755 "$SRC" "$DEST"
echo "Installed: $DEST"

if ! command -v "$SCRIPT_NAME" &>/dev/null; then
    echo ""
    echo "NOTA: $HOME/bin non è nel PATH."
    echo "Aggiungi questa riga al tuo ~/.bashrc o ~/.bash_profile:"
    echo ""
    echo "    export PATH=\"\$HOME/bin:\$PATH\""
fi
