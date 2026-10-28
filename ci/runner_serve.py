#!/usr/bin/env python3
"""Runner side of the nxnative build transfer.

Starts a token-protected HTTP server for the finished IPA, exposes it through
a Cloudflare quick tunnel, tells the local machine where it is, and keeps the
tunnel alive until the local machine confirms the download.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

CHUNK = 1024 * 1024


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
    def __init__(self, file: Path, token: str) -> None:
        self.file = file
        self.token = token
        self.done_payload: dict | None = None
        self.done_event = threading.Event()

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

    def _range_error(self, size: int) -> None:
        self.send_response(416)
        self.send_header("Content-Range", f"bytes */{size}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _serve(self) -> None:
        path = self.app.file
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

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"ok": True})
            return
        if not self.app.authorized(self.headers.get("Authorization")):
            self._error(401, "unauthorized")
            return
        if path == "/status":
            self._json(
                200,
                {
                    "ok": True,
                    "done": self.app.done_event.is_set(),
                    "file": self.app.file.name,
                    "size": self.app.file.stat().st_size,
                },
            )
            return
        if path == "/ipa":
            self._serve()
            return
        self._error(404, "not found")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/done":
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
            self._error(413, "done body too large")
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (ValueError, OSError):
            self._error(400, "bad JSON")
            return
        if not isinstance(payload, dict):
            self._error(400, "bad JSON")
            return
        self._json(200, {"ok": True})
        self.app.done_payload = payload
        self.app.done_event.set()


def start_tunnel(binary: str, port: int) -> tuple[subprocess.Popen, str]:
    command = [
        binary,
        "--no-autoupdate",
        "tunnel",
        "--url",
        f"http://127.0.0.1:{port}",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    url_holder: dict[str, str] = {}
    ready = threading.Event()

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
            if match and "url" not in url_holder:
                url_holder["url"] = match.group(0)
                ready.set()

    threading.Thread(target=reader, daemon=True).start()
    for _ in range(120):
        if ready.wait(1):
            return process, url_holder["url"]
        if process.poll() is not None:
            raise RuntimeError(f"cloudflared exited with status {process.returncode}")
    process.terminate()
    raise RuntimeError("cloudflared did not print a tunnel URL within 120 seconds")


def post_json(url: str, token: str, payload: dict, tries: int = 60) -> None:
    data = json.dumps(payload).encode()
    last_error: Exception | None = None
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
                    return
                last_error = RuntimeError(f"HTTP {response.status}")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        if attempt % 5 == 0:
            print(f"  waiting for the local machine to accept the callback: {last_error}")
        time.sleep(min(5 + attempt, 30))
    raise RuntimeError(f"could not reach the local callback: {last_error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, help="the finished IPA")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--token", default=os.environ.get("BUILD_TOKEN", ""))
    parser.add_argument("--callback-url", required=True, help="local /callback URL")
    parser.add_argument("--timeout", type=int, default=4 * 3600, help="seconds to wait for the local download")
    parser.add_argument("--cloudflared", default=shutil.which("cloudflared") or "cloudflared")
    args = parser.parse_args(argv)
    if not args.token:
        parser.error("--token or BUILD_TOKEN is required")
    if urlparse(args.callback_url).scheme not in ("http", "https"):
        parser.error("--callback-url must be http(s)")

    file = Path(args.file).expanduser().resolve()
    if not file.is_file():
        parser.error(f"no such file: {file}")

    app = App(file=file, token=args.token)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.app = app  # type: ignore[attr-defined]
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"serving {file.name} locally on http://127.0.0.1:{args.port}/ipa")

    tunnel_process: subprocess.Popen | None = None
    try:
        print("starting Cloudflare quick tunnel...")
        tunnel_process, tunnel_url = start_tunnel(args.cloudflared, args.port)
        print(f"tunnel: {tunnel_url}")
        print("hashing the IPA...")
        size = file.stat().st_size
        digest = sha256_file(file)
        print(f"IPA: {human_bytes(size)}, sha256 {digest}")
        payload = {
            "ipa_url": tunnel_url + "/ipa",
            "done_url": tunnel_url + "/done",
            "sha256": digest,
            "size": size,
            "filename": file.name,
        }
        print(f"posting callback to {args.callback_url} ...")
        post_json(args.callback_url, args.token, payload)
        print(f"waiting up to {args.timeout / 3600:.1f}h for the local download...")
        if not app.done_event.wait(args.timeout):
            print("timed out waiting for the local machine to finish the download")
            return 1
        print(f"local result: {json.dumps(app.done_payload)}")
        return 0 if app.done_payload and app.done_payload.get("status") == "ok" else 1
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    finally:
        if tunnel_process is not None:
            tunnel_process.terminate()
            try:
                tunnel_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                tunnel_process.kill()
        server.shutdown()
        server.server_close()


def _terminate(*_: object) -> None:
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _terminate)
    raise SystemExit(main())
