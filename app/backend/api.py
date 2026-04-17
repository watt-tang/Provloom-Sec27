from __future__ import annotations

import json
from wsgiref.util import setup_testing_defaults

from app.analyzer.rules import analyze_trace
from app.backend.schemas import AnalyzeSkillRequest, AnalyzeSkillResponse
from app.runner.docker_runner import DockerRunner, DockerUnavailableError, SandboxRunError

runner = DockerRunner()


def application(environ, start_response):
    setup_testing_defaults(environ)
    method = environ["REQUEST_METHOD"]
    path = environ.get("PATH_INFO", "")

    if method == "GET" and path == "/health":
        return _json_response(start_response, 200, {"status": "ok"})
    if method == "POST" and path == "/analyze-skill":
        return _handle_analyze_skill(environ, start_response)

    return _json_response(start_response, 404, {"error": "Not found"})


def _handle_analyze_skill(environ, start_response):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw_body = environ["wsgi.input"].read(length).decode("utf-8") if length > 0 else "{}"
        payload = AnalyzeSkillRequest.from_dict(json.loads(raw_body))

        execution = runner.run(
            skill_path=payload.skill_path,
            command=payload.command,
            timeout_seconds=payload.timeout_seconds,
        )
        report = analyze_trace(execution)
        response = AnalyzeSkillResponse(
            skill_path=execution.skill_path,
            sandbox_image=execution.sandbox_image,
            command=execution.command,
            exit_code=execution.exit_code,
            timed_out=execution.timed_out,
            stdout=execution.stdout,
            stderr=execution.stderr,
            trace_summary=report["trace_summary"],
            risk_score=report["risk_score"],
            detected_behaviors=report["detected_behaviors"],
            evidence_timeline=report["evidence_timeline"],
        )
        return _json_response(start_response, 200, response.to_dict())
    except json.JSONDecodeError as exc:
        return _json_response(start_response, 400, {"error": f"Invalid JSON: {exc}"})
    except ValueError as exc:
        return _json_response(start_response, 400, {"error": str(exc)})
    except DockerUnavailableError as exc:
        return _json_response(start_response, 503, {"error": str(exc)})
    except SandboxRunError as exc:
        return _json_response(start_response, 400, {"error": str(exc)})
    except Exception as exc:  # pragma: no cover - defensive fallback
        return _json_response(start_response, 500, {"error": f"Unexpected sandbox failure: {exc}"})


def _json_response(start_response, status_code: int, payload: dict):
    status_text = {
        200: "200 OK",
        400: "400 Bad Request",
        404: "404 Not Found",
        500: "500 Internal Server Error",
        503: "503 Service Unavailable",
    }[status_code]
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    start_response(status_text, headers)
    return [body]
