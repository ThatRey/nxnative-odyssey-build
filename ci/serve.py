#!/usr/bin/env python3
"""Local side of the nxnative build transfer.

Serves the game files to the GitHub runner over a token-protected tunnel,
waits for the runner to offer the finished IPA, downloads it with resume,
checks its SHA-256, and tells the runner the transfer is done.

Only the three named files are served.  Nothing is written outside --out.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

CHUNK = 1024 * 1024
GAME_FILES = ("base.nsp", "update.nsp", "prod.keys")


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TiB"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class App:
    def __init__(self, root: Path, out: Path, token: str, ipa_name: str) -> None:
        self.root = root
        self.out = out
        self.token = token
        self.ipa_name = ipa_name
        self.callback: dict | None = None
        self.callback_event = threading.Event()
        self.phase = "waiting for runner"

    def authorized(self, header: str | None) -> bool:
        return hmac.compare_digest(header or "", "Bearer " + self.token)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nxnative-transfer/1.0"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s %s\n" % (time.strftime("%H:%M:%S"), fmt % args))
        sys.stderr.flush()

    def _json(self, code: int, obj: dict, close: bool = False) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        if close:
            self.close_connection = True

    def _error(self, code: int, message: str) -> None:
        self._json(code, {"error": message}, close=True)

    def _serve(self, path: Path) -> None:
        try:
            f = path.open("rb")
        except OSError:
            self._error(404, "not found")
            return
        with f:
            size = os.fstat(f.fileno()).st_size
            start, end = 0, size - 1
            range_header = self.headers.get("Range")
            if range_header:
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header.strip())
                if not match:
                    self._range_error(size)
                    return
                first, last = match.groups()
                if first:
                    start = int(first)
                    if last:
                        end = min(int(last), size - 1)
                else:
                    suffix = int(last or "0")
                    if suffix <= 0:
                        self._range_error(size)
                        return
                    start = max(size - suffix, 0)
                if start > end or start >= size:
                    self._range_error(size)
                    return
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            else:
                self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(max(0, end - start + 1)))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
            self.end_headers()
            if self.command == "HEAD":
                return
            f.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                    return
                remaining -= len(chunk)

    def _range_error(self, size: int) -> None:
        self.send_response(416)
        self.send_header("Content-Range", f"bytes */{size}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"ok": True, "phase": self.app.phase})
            return
        if not self.app.authorized(self.headers.get("Authorization")):
            self._error(401, "unauthorized")
            return
        if path == "/status":
            callback = self.app.callback or {}
            self._json(
                200,
                {
                    "ok": True,
                    "phase": self.app.phase,
                    "callback": {
                        key: callback.get(key)
                        for key in ("filename", "size", "sha256")
                    },
                },
            )
            return
        names = {"/" + name: self.app.root / name for name in GAME_FILES}
        if path in names:
            self._serve(names[path])
            return
        self._error(404, "not found")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/callback":
            self._error(404, "not found")
            return
        if not self.app.authorized(self.headers.get("Authorization")):
            self._error(401, "unauthorized")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._error(400, "bad Content-Length")
            return
        if length <= 0 or length > 65536:
            self._error(413, "callback body too large")
            return
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, OSError):
            self._error(400, "bad JSON")
            return
        if not isinstance(data, dict):
            self._error(400, "bad JSON")
            return
        ipa_url = data.get("ipa_url")
        done_url = data.get("done_url")
        sha = data.get("sha256")
        size = data.get("size")
        filename = data.get("filename") or "game.ipa"
        if not isinstance(ipa_url, str) or urlparse(ipa_url).scheme not in ("http", "https"):
            self._error(400, "bad ipa_url")
            return
        if not isinstance(done_url, str) or urlparse(done_url).scheme not in ("http", "https"):
            self._error(400, "bad done_url")
            return
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
            self._error(400, "bad sha256")
            return
        try:
            size = int(size)
        except (TypeError, ValueError):
            self._error(400, "bad size")
            return
        if size <= 0:
            self._error(400, "bad size")
            return
        entry = {
            "ipa_url": ipa_url,
            "done_url": done_url,
            "sha256": sha.lower(),
            "size": size,
            "filename": str(filename)[:200],
        }
        if self.app.callback is None:
            self.app.callback = entry
            self.app.phase = "downloading IPA"
            self.app.callback_event.set()
            self._json(200, {"ok": True})
        elif self.app.callback.get("ipa_url") == ipa_url:
            self._json(200, {"ok": True, "duplicate": True})
        else:
            self._error(409, "already have a callback")


def open_range(url: str, token: str, pos: int):
    headers = {
        "Authorization": "Bearer " + token,
        "User-Agent": "nxnative-transfer/1.0",
    }
    if pos:
        headers["Range"] = f"bytes={pos}-"
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request, timeout=120)


def download(url: str, dest: Path, token: str, total: int, expected_sha: str) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        if dest.stat().st_size == total and sha256_file(dest).lower() == expected_sha.lower():
            print(f"  already have {dest}")
            return dest
        print(f"  replacing incomplete or mismatched {dest}")
        dest.unlink()
    part = dest.with_name(dest.name + ".part")
    pos = part.stat().st_size if part.is_file() else 0
    if pos > total:
        part.unlink()
        pos = 0
    started = time.time()
    last_report = 0.0
    attempt = 0
    while pos < total:
        attempt += 1
        try:
            with open_range(url, token, pos) as response:
                if response.status == 200 and pos:
                    print("\n  server ignored Range; restarting from zero")
                    part.unlink()
                    pos = 0
                    continue
                if response.status not in (200, 206):
                    raise RuntimeError(f"HTTP {response.status}")
                if response.status == 206:
                    content_range = response.headers.get("Content-Range", "")
                    match = re.match(r"bytes (\d+)-", content_range)
                    if match and int(match.group(1)) != pos:
                        raise RuntimeError(f"unexpected Content-Range {content_range!r}")
                with part.open("ab") as f:
                    while True:
                        chunk = response.read(CHUNK)
                        if not chunk:
                            break
                        f.write(chunk)
                        pos += len(chunk)
                        if pos > total:
                            raise RuntimeError("server sent more bytes than announced")
                        now = time.time()
                        if now - last_report >= 5:
                            last_report = now
                            pct = 100.0 * pos / total
                            elapsed = now - started
                            speed = pos / elapsed if elapsed else 0
                            line = (
                                f"  IPA download: {human_bytes(pos)} / {human_bytes(total)} "
                                f"({pct:5.1f}%) at {human_bytes(speed)}/s"
                            )
                            if sys.stdout.isatty():
                                sys.stdout.write("\r" + line + "   ")
                            else:
                                print(line)
                            sys.stdout.flush()
        except Exception as exc:  # noqa: BLE001 - every network failure is retried
            try:
                pos = part.stat().st_size
            except OSError:
                pos = 0
            if pos > total:
                part.unlink(missing_ok=True)
                pos = 0
            print(f"\n  download interrupted at {human_bytes(pos)}: {exc}")
            if attempt >= 120:
                raise
            time.sleep(min(5 * attempt, 60))
    if part.stat().st_size != total:
        raise RuntimeError(f"downloaded {part.stat().st_size} bytes, expected {total}")
    print(f"\n  checking SHA-256 of {human_bytes(total)} (this takes a moment)...")
    sha = sha256_file(part)
    if sha.lower() != expected_sha.lower():
        raise RuntimeError(f"SHA-256 mismatch: got {sha}, expected {expected_sha}")
    if dest.exists():
        dest.unlink()
    part.replace(dest)
    return dest


def post_json(url: str, token: str, payload: dict, tries: int = 20) -> bool:
    data = json.dumps(payload).encode()
    for attempt in range(tries):
        request = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "User-Agent": "nxnative-transfer/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if 200 <= response.status < 300:
                    return True
        except Exception as exc:  # noqa: BLE001
            print(f"  callback to runner failed ({attempt + 1}/{tries}): {exc}")
        time.sleep(min(2**attempt, 30))
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="game", help="folder with base.nsp, update.nsp and prod.keys")
    parser.add_argument("--out", default="out", help="folder for the downloaded IPA")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--token", default=os.environ.get("BUILD_TOKEN", ""))
    parser.add_argument("--ipa-name", default="Odyssey.ipa")
    parser.add_argument("--wait", type=int, default=6 * 3600, help="seconds to wait for the runner callback")
    args = parser.parse_args(argv)
    if not args.token:
        parser.error("--token or BUILD_TOKEN is required")

    root = Path(args.root).expanduser().resolve()
    for name in GAME_FILES:
        if not (root / name).is_file():
            parser.error(f"missing {root / name}")
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    app = App(root=root, out=out, token=args.token, ipa_name=args.ipa_name)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.app = app  # type: ignore[attr-defined]
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"local server on http://127.0.0.1:{args.port} (token-protected)")
    print(f"serving: {', '.join(GAME_FILES)} from {root}")
    print(f"waiting for the runner callback (up to {args.wait / 3600:.1f}h)...")
    try:
        if not app.callback_event.wait(args.wait):
            print("timed out waiting for the runner callback")
            return 1
        callback = app.callback
        assert callback is not None
        print(
            f"runner offers {callback['filename']} "
            f"({human_bytes(callback['size'])}, sha256 {callback['sha256'][:12]}...)"
        )
        dest = out / args.ipa_name
        try:
            path = download(
                callback["ipa_url"],
                dest,
                args.token,
                callback["size"],
                callback["sha256"],
            )
        except Exception as exc:  # noqa: BLE001
            print(f"IPA download failed: {exc}")
            post_json(
                callback["done_url"],
                args.token,
                {"status": "error", "error": str(exc)[:500]},
            )
            return 1
        if not post_json(
            callback["done_url"],
            args.token,
            {
                "status": "ok",
                "sha256": callback["sha256"],
                "size": callback["size"],
            },
        ):
            print("warning: could not notify the runner; it will stop on its own timeout")
        print(f"IPA ready: {path}")
        print(f"SHA-256: {callback['sha256']}")
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
