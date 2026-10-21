#!/usr/bin/env bash
# Poll for the advisory/PoC; detonate anything new in the ASAN/CGI lab, then note whether to test prod.
# Runs unattended:  ./lab/watch-release.sh &   (log: /tmp/php2shell-watch.log)
set -uo pipefail
LOG=/tmp/php2shell-watch.log; SEEN=/tmp/php2shell-seen.txt; OUT=/tmp/php2shell-samples
mkdir -p "$OUT"; touch "$SEEN"
say(){ echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
say "watcher up (500s cadence): php.net releases/tags + PoC repos"

fetch(){ curl -sS --max-time 25 -L "$1" 2>/dev/null; }
repo_files(){ fetch "https://api.github.com/repos/$1/contents/" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
if isinstance(d,dict): raise SystemExit
for i in d:
    u=i.get('download_url') or ''
    if i.get('type')=='file' and (u.endswith('.py') or u.endswith('.sh') or u.endswith('.md')):
        print(u)" 2>/dev/null; }

while true; do
  # 1. release page: bumped = fixed builds exist
  rel=$(fetch https://www.php.net/releases/index.php?json | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
for b in d:
    vs=d[b].get('version') or []
    print(b, vs[0] if isinstance(vs,list) and vs else vs)" 2>/dev/null)
  if [ -n "${rel:-}" ]; then
    new=$(comm -13 <(sort "$SEEN" 2>/dev/null) <(echo "$rel" | sort) | head -3)
    if [ -n "$new" ]; then echo "$rel" | sort > "$SEEN"; say "RELEASE MOVED: $(echo "$new" | tr '\n' ' ')"; fi
  fi
  # 2. PoC repos
  for r in 0ldbaby/php2shell Icex0/php2shell-poc Wenenu/php2shell NeaByteLab/php2shell veka-server/PHP2shell; do
    for u in $(repo_files "$r"); do
      f="$OUT/$(echo "$r$u" | tr '/' '_')"
      [ -f "$f" ] && continue
      curl -sS --max-time 30 -L "$u" -o "$f" 2>/dev/null || continue
      say "SAMPLE: $r -> $f ($(wc -c <"$f") bytes)"
      case "$f" in
        *.py|*.sh|*.php) (cd /var/lib/hermes/playground/php2shell-scan && timeout 600 ./lab/detonate.sh "$f" http://127.0.0.1:8082 >>"$LOG" 2>&1) ;;
      esac
    done
  done
  sleep 500
done
