#!/usr/bin/env bash
# Fire a sample at the lab. Usage: ./detonate.sh <poc.py|poc.sh> [target-url]
# Keeps: full fpm/nginx log slices, any core, and the sample's own stdout.
set -uo pipefail
POC=${1:?sample path}
T=${2:-http://127.0.0.1:8081}
LAB=$(cd "$(dirname "$0")" && pwd)
before=$(wc -l < "$LAB/fpm-error.log" 2>/dev/null || echo 0)
before_pids=$(pgrep -f "php-fpm: pool" | wc -l)
echo "== detonating $POC against $T (baseline deaths before: $(grep -ci signal "$LAB/fpm-error.log" 2>/dev/null || echo 0))"
case "$POC" in
  *.py) timeout 900 python3 "$POC" "$T" ;;
  *)    timeout 900 bash "$POC" "$T" ;;
esac
rc=$?
echo "== sample exit: $rc"
sleep 1
echo "== new fpm log:"; tail -n +$((before+1)) "$LAB/fpm-error.log" 2>/dev/null | grep -iE 'signal|segv|warning|error' | tail -20
echo "== pool children: before=$before_pids now=$(pgrep -f 'php-fpm: pool' | wc -l)"
ls -t /var/lib/systemd/coredump/core* 2>/dev/null | head -3
exit $rc
