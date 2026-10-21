#!/usr/bin/env bash
# Undo install.sh
set -uo pipefail
WEB=${1:-public}
[ -f "$WEB/index.php.pre-deface.bak" ] && mv -f "$WEB/index.php.pre-deface.bak" "$WEB/index.php"
rm -f "$WEB/index.html" "$WEB/deface.jpg"
echo "restored $WEB"
