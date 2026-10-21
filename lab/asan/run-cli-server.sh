#!/usr/bin/env bash
cd /tmp/asan-lab
export USE_ZEND_ALLOC=0
export PHP_CLI_SERVER_WORKERS=4
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:halt_on_error=1:log_path=/tmp/asan-lab/asan:handle_abort=1"
export PHP_INI_SCAN_DIR=""
while true; do
  /tmp/php-asan/php-8.4.19/sapi/cli/php -d session.upload_progress.enabled=On \
    -d session.upload_progress.cleanup=On -d session.save_path=/tmp/asan-lab/sess \
    -d error_reporting=0 -d display_errors=0 -d max_file_uploads=20 \
    -S 127.0.0.1:8090 router.php >> /tmp/asan-lab/server.log 2>&1
  echo "[restart $(date +%T)]" >> /tmp/asan-lab/server.log
  sleep 0.3
done
