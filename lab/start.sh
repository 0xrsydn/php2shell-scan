#!/usr/bin/env bash
# Start the detonation lab. Needs: nix shell nixpkgs#php nixpkgs#nginx
set -euo pipefail
LAB=$(cd "$(dirname "$0")" && pwd)
RUN=/tmp/php2shell-lab
mkdir -p "$RUN/www" "$RUN/sess"
cp -r "$LAB/www/." "$RUN/www/"
sed "s#/var/lib/hermes/playground/lab#$RUN#g; s#RUN_DIR#$RUN#g" "$LAB/fpm.conf" > "$RUN/fpm.conf"
command -v nginx >/dev/null || { echo "run me inside: nix shell nixpkgs#php nixpkgs#nginx"; exit 1; }
php-fpm -y "$RUN/fpm.conf" &
FPM=$!
trap 'kill $FPM 2>/dev/null' EXIT INT TERM
sleep 1
echo "lab up: http://127.0.0.1:8081 (fpm pid $FPM, logs $RUN)" >&2
exec nginx -c "$LAB/nginx.conf" -p "$LAB"
