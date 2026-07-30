from __future__ import annotations

import argparse
import hashlib
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse


class CaptureHandler(BaseHTTPRequestHandler):
    server: "CaptureHTTPServer"

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 - inherited name
        return None

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._respond(200, "ok\n")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        record = {
            "service_id": self.server.service_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "host": self.headers.get("Host", ""),
            "port": self.server.server_port,
            "path": parsed.path or "/",
            "query_keys": sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}),
            "header_names": sorted(str(key) for key in self.headers.keys()),
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
            "uploaded_filenames": _multipart_filenames(body, self.headers.get("Content-Type", "")),
            "taint_ids": [],
            "redacted_preview": _redacted_preview(body),
            "plaintext_stored": False,
            "response_status": self.server.response_status,
        }
        self.server.write_record(record)
        self._respond(self.server.response_status, self.server.response_body)

    def _respond(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class CaptureHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], handler, *, service: dict[str, Any], record_dir: Path) -> None:
        super().__init__(server_address, handler)
        self.service_id = str(service.get("service_id") or f"mock-{server_address[1]}")
        self.response_status = int(service.get("response_status", 200))
        self.response_body = str(service.get("response_body", "OK\n"))
        self.record_path = record_dir / f"{self.service_id}-{server_address[1]}.jsonl"
        self.record_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write_record(self, record: dict[str, Any]) -> None:
        with self._lock:
            with self.record_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_servers(config_path: Path) -> int:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    record_dir = Path(payload.get("record_dir") or "/artifacts/mock-services")
    servers: list[CaptureHTTPServer] = []
    threads: list[threading.Thread] = []
    for service in payload.get("services", []) or []:
        port = int(service["port"])
        server = CaptureHTTPServer(("127.0.0.1", port), CaptureHandler, service=service, record_dir=record_dir)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
    ready = {
        "status": "ready",
        "services": [
            {"service_id": server.service_id, "port": server.server_port, "record_path": str(server.record_path)}
            for server in servers
        ],
    }
    (record_dir / "mock-services-ready.json").write_text(json.dumps(ready, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        threading.Event().wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    return 0


def _redacted_preview(body: bytes) -> dict[str, Any]:
    if not body:
        return {"redacted": "", "byte_count": 0, "plaintext_stored": False}
    return {
        "redacted": "[REQUEST_BODY_PREVIEW_REDACTED]",
        "byte_count": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "plaintext_stored": False,
    }


def _multipart_filenames(body: bytes, content_type: str) -> list[str]:
    if "multipart/form-data" not in content_type.lower() or not body:
        return []
    text = body.decode("utf-8", errors="replace")
    names: list[str] = []
    marker = 'filename="'
    start = 0
    while True:
        index = text.find(marker, start)
        if index == -1:
            break
        end = text.find('"', index + len(marker))
        if end == -1:
            break
        names.append(text[index + len(marker):end])
        start = end + 1
    return sorted(set(names))


def main() -> int:
    parser = argparse.ArgumentParser(description="ProvLoom fixture mock capture server")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    return run_servers(Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
