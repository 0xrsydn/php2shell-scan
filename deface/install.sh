#!/usr/bin/env bash
# Drop the deface page into a webroot. Assumes local access to the box (shell/ptrace/ssh).
#   ./install.sh /path/to/public            # default: ./public
# Keeps a timestamped backup so restore.sh can undo it.
set -uo pipefail
FORCE=0; WEB=public
for arg in "$@"; do
  case "$arg" in --force) FORCE=1 ;; *) WEB=$arg ;; esac
done
[ -d "$WEB" ] || { echo "no such webroot: $WEB" >&2; exit 1; }
STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
here=$(cd "$(dirname "$0")" && pwd)
cp -a "$WEB/index.php" "$WEB/index.php.pre-deface.bak" 2>/dev/null
# exact page from the template, with the stamp filled in
sed "s|__STAMP__|$STAMP|" "$here/index.html" > "$WEB/index.html"
cp -a "$here/deface.jpg" "$WEB/deface.jpg"
# nginx here sets `index index.php`, so index.html alone is never reached: the front
# controller is replaced outright. The identical markup also stays as index.html for
# stacks where index.html wins, and index.php.pre-deface.bak is the way back.
sed "s|__STAMP__|$STAMP|" "$here/index.html" > "$WEB/index.php"
echo "index.php replaced (backup: index.php.pre-deface.bak); index.html also written"
ls -la "$WEB/index.html" "$WEB/deface.jpg"
