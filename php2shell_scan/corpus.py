"""Multipart corpus: the shapes that reach PHP's RFC1867 and upload-progress code."""
from __future__ import annotations

import base64
import random
import string

PROGRESS = "PHP_SESSION_UPLOAD_PROGRESS"
TSPECIAL = set('()<>@,;:\\"/[]?=')


def boundary(n: int = 24) -> str:
    return "----php2shell" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def part(name: str, value: bytes | str = b"", filename: str | bytes | None = None,
         extra: tuple = (), cte: str | None = None) -> bytes:
    out = [b"--BOUNDARY"]
    if filename is None:
        out.append(b'Content-Disposition: form-data; name="%s"' % name.encode())
    else:
        fn = filename.encode() if isinstance(filename, str) else filename
        out.append(b'Content-Disposition: form-data; name="%s"; filename="%s"' % (name.encode(), fn))
        out.append(b"Content-Type: application/octet-stream")
    if cte:
        out.append(b"Content-Transfer-Encoding: " + cte.encode())
    out.extend(extra)
    out.append(b"")
    out.append(value if isinstance(value, bytes) else value.encode())
    return b"\r\n".join(out)


def build(name: str, parts: list[bytes], *, end: bool = True, epilogue: bytes = b"",
          bnd: str | None = None) -> tuple[str, dict, bytes]:
    bnd = bnd or boundary()
    body = b"\r\n".join(parts)
    if end:
        body += b"\r\n--BOUNDARY--\r\n"
    body = body + epilogue
    body = body.replace(b"--BOUNDARY", b"--" + bnd.encode())
    q = bnd if not (set(bnd) & TSPECIAL) else '"' + bnd.replace('"', '\\"') + '"'
    return name, {"Content-Type": f"multipart/form-data; boundary={q}"}, body


def case(name: str) -> tuple[str, dict, bytes]:
    """A single named case. Unknown names raise KeyError."""
    f = part("f", b"A" * 64, filename="a.txt")
    if name == "clean":
        return build(name, [part("nama", "x"), part("email", "a@b.c")])
    if name == "file":
        return build(name, [f])
    if name == "progress":
        return build(name, [part(PROGRESS, "p1"), f])
    if name == "progress-array":
        return build(name, [part(PROGRESS + "[]", "p2"), f])
    if name == "progress-separators":
        return build(name, [part(PROGRESS, "a|b|c"), part(PROGRESS, "k|v"), f])
    if name == "progress-dup":
        return build(name, [part(PROGRESS, "one"), part(PROGRESS, "two"), f])
    if name == "progress-collide":
        return build(name, [part(PROGRESS, "f"), f])
    if name == "progress-nested":
        return build(name, [part(PROGRESS + "[a][b][c]", "v"), f])
    if name == "progress-empty":
        return build(name, [part(PROGRESS, ""), f])
    if name == "progress-big":
        return build(name, [part(PROGRESS, "p"), part("f", b"F" * 262144, filename="big.bin")])
    if name == "deep-names":
        return build(name, [part("a" + "[k]" * 14, "v"), f])
    if name == "long-boundary":
        return build(name, [part("a", "v")], bnd=boundary(200))
    if name == "weird-boundary":
        return build(name, [part("a", "v")], bnd="_'()+_,-./:=?" + boundary(12))
    if name == "no-final-boundary":
        return build(name, [part("a", "v")], end=False)
    if name == "epilogue":
        return build(name, [part("a", "v"), part(PROGRESS, "ep")], epilogue=b"junk\r\n")
    if name == "dup-content-disposition":
        return build(name, [b"\r\n".join([b"--BOUNDARY", b'Content-Disposition: form-data; name="a"',
                                          b'Content-Disposition: form-data; name="b"', b"", b"v"])])
    if name == "filename-star":
        return build(name, [b"\r\n".join([b"--BOUNDARY",
                                          b"Content-Disposition: form-data; name=\"f\"; "
                                          b"filename=\"a.txt\"; filename*=UTF-8''%E2%82%AC.txt",
                                          b"Content-Type: text/plain", b"", b"v"])])
    if name == "nul-filename":
        return build(name, [part("f", b"v", filename=b"a\x00.php")])
    if name == "empty-filename":
        return build(name, [part("f", b"", filename="")])
    if name == "cte-base64":
        return build(name, [part("f", base64.b64encode(b"x" * 48), filename="e.txt", cte="base64")])
    if name == "nested-file-array":
        return build(name, [part("files[a][b][]", b"q" * 32, filename="g.txt")])
    if name == "many-files":
        return build(name, [part(f"f{i}", b"n", filename=f"{i}.txt") for i in range(25)])
    if name == "progress-as-file":
        return build(name, [part(PROGRESS, b"v", filename="p.txt"), f])
    if name == "progress-after-file":
        return build(name, [f, part(PROGRESS, "late")])
    if name == "sid-in-body":
        return build(name, [part(PROGRESS, "p"), part("PHPSESSID", "abc123"), f])
    if name == "sid-after-file":
        return build(name, [f, part(PROGRESS, "p"), part("PHPSESSID", "abc123")])
    if name == "sid-and-dup-progress":
        return build(name, [part(PROGRESS, "p"), part(PROGRESS, "dup"),
                            part("PHPSESSID", "abc123"), f])
    if name == "progress-nul-value":
        return build(name, [part(PROGRESS, "a\x00b"), f])
    raise KeyError(name)


CASES = ["clean", "file", "progress", "progress-array", "progress-separators", "progress-dup",
         "progress-collide", "progress-nested", "progress-empty", "deep-names", "long-boundary",
         "weird-boundary", "no-final-boundary", "epilogue", "dup-content-disposition",
         "filename-star", "nul-filename", "empty-filename", "cte-base64", "nested-file-array",
         "many-files", "progress-as-file", "progress-after-file", "progress-nul-value",
         "sid-in-body", "sid-after-file", "sid-and-dup-progress"]

HEAVY = ["progress-big", "many-parts"]


def many_parts() -> tuple[str, dict, bytes]:
    return build("many-parts", [part(f"p{i}", "v") for i in range(1100)])


def rand() -> tuple[str, dict, bytes]:
    """Randomised heap-shaping shape: key sizes, duplicates, files, shuffle, upload overflow."""
    parts: list[bytes] = []
    for _ in range(random.randint(1, 6)):
        n = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512])
        val = "v" * n if random.random() < .5 else "|".join("k" * (n // 4) or "k")
        parts.append(part(PROGRESS, val))
    for _ in range(random.randint(0, 3)):
        parts.append(part("f", b"Z" * random.randint(0, 2048), filename="r.txt"))
    if random.random() < .3:
        parts += [part(f"o{i}", b"y", filename=f"{i}.txt") for i in range(25)]
    random.shuffle(parts)
    return build("rand", parts)


def corpus(heavy: bool = False) -> list[tuple[str, dict, bytes]]:
    out = [case(n) for n in CASES]
    if heavy:
        out += [case("progress-big"), many_parts()]
    return out
