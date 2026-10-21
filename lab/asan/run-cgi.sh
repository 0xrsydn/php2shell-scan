#!/usr/bin/env bash
export USE_ZEND_ALLOC=0
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:halt_on_error=1:log_path=/tmp/asan-lab/asan:handle_abort=1"
while true; do
  /tmp/php-asan/php-8.4.19/sapi/cgi/php-cgi -b 127.0.0.1:9001 \
    -d session.upload_progress.enabled=On -d session.upload_progress.cleanup=On \
    -d session.save_path=/tmp/asan-lab/sess -d max_file_uploads=20 \
    -d error_reporting=0 -d display_errors=0 >> /tmp/asan-lab/cgi.log 2>&1
  echo "[restart $(date +%T)]" >> /tmp/asan-lab/cgi.log; sleep 0.3
done
