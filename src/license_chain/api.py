"""无第三方依赖的许可与流转 HTTP JSON 接口。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import LicenseChainError, ValidationFailed
from .service import LicenseChainService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    def __init__(self, service: LicenseChainService) -> None:
        self.service = service

    @staticmethod
    def _actor(headers: Mapping[str, str]) -> str:
        actor = headers.get("x-actor-id", "").strip()
        if not actor:
            raise ValidationFailed("缺少 X-Actor-Id")
        return actor

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    def handle(self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b"") -> Response:
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            actor = self._actor(normalized)
            if method == "POST" and path == "/users":
                return Response(201, self.service.create_user(payload["user_id"], payload["display_name"], payload["role"]))
            if method == "POST" and path == "/licenses":
                return Response(201, self.service.register_license(actor, payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "licenses" and parts[2] == "scopes":
                return Response(201, self.service.add_license_scope(actor, parts[1], payload))
            if method == "GET" and len(parts) == 2 and parts[0] == "licenses":
                return Response(200, self.service.license(parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "licenses" and parts[2] == "revoke":
                return Response(200, self.service.revoke_license(actor, parts[1], payload["effective_on"], payload["reason"]))
            if method == "POST" and path == "/sites":
                return Response(201, self.service.register_site(actor, payload))
            if method == "POST" and len(parts) == 3 and parts[0] == "sites" and parts[2] == "revoke":
                return Response(200, self.service.revoke_site(actor, parts[1], payload["effective_on"], payload["reason"]))
            if method == "GET" and len(parts) == 2 and parts[0] == "sites":
                return Response(200, self.service.site(parts[1]))
            if method == "POST" and path == "/batches":
                return Response(201, self.service.register_batch(actor, payload))
            if method == "GET" and len(parts) == 2 and parts[0] == "batches":
                return Response(200, self.service.batch(parts[1]))
            if method == "POST" and path == "/handovers":
                result = self.service.record_handover(actor, payload)
                return Response(201 if result["decision"] == "recorded" else 200, result)
            if method == "GET" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "chain":
                return Response(200, self.service.chain_trace(actor, parts[1]))
            if method == "GET" and path == "/authorization":
                return Response(
                    200,
                    self.service.authorization_at(
                        actor,
                        query["batch_id"][0],
                        query["unit_id"][0],
                        query["action"][0],
                        query["on"][0],
                    ),
                )
            if method == "POST" and path == "/reviews":
                return Response(201, self.service.open_review(actor, payload["review_id"], payload["batch_id"], payload["as_of_on"]))
            if method == "POST" and len(parts) == 3 and parts[0] == "reviews" and parts[2] == "close":
                return Response(200, self.service.close_review(actor, parts[1]))
            if method == "POST" and len(parts) == 3 and parts[0] == "reviews" and parts[2] == "refresh":
                return Response(200, self.service.refresh_review(actor, parts[1]))
            if method == "GET" and len(parts) == 2 and parts[0] == "reviews":
                return Response(200, self.service.review(actor, parts[1]))
            if method == "GET" and path == "/audit/chain":
                return Response(200, self.service.audit_chain(actor))
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        except LicenseChainError as exc:
            body = {"error": {"code": exc.code, "message": str(exc)}}
            if exc.details is not None:
                body["error"]["details"] = exc.details
            return Response(exc.status, body)
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LicenseChain/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动核技术应用许可与流转服务")
    parser.add_argument("--database", type=Path, default=Path("license_chain.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8083)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(JsonApplication(LicenseChainService(connection))))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
