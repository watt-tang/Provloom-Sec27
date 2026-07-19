from __future__ import annotations

import json
import uuid
from pathlib import Path
from wsgiref.util import setup_testing_defaults

from app.analyzer.rules import analyze_static_skill, analyze_trace
from app.backend.log_writer import ExecutionLogWriter
from app.backend.schemas import AnalyzeSkillRequest, AnalyzeSkillResponse, TaskResponse
from app.backend.task_store import TaskStore
from app.reporting.risk_mapper import map_risk_profile
from app.runtime.skill_parser import load_skill_definition, resolve_skill_target
from app.runner.docker_runner import DockerRunner, DockerUnavailableError, SandboxRunError
from app.telemetry.collector import build_execution_report

runner = DockerRunner()
task_store = TaskStore()
log_writer = ExecutionLogWriter()


def application(environ, start_response):
    setup_testing_defaults(environ)
    method = environ["REQUEST_METHOD"]
    path = environ.get("PATH_INFO", "")

    if method == "GET" and path == "/health":
        return _json_response(start_response, 200, {"status": "ok"})
    if method == "POST" and path == "/analyze-skill":
        return _handle_analyze_skill(environ, start_response)
    if method == "GET" and path.startswith("/task/"):
        return _handle_get_task(path, start_response)

    return _json_response(start_response, 404, {"error": "Not found"})


def _handle_analyze_skill(environ, start_response):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw_body = environ["wsgi.input"].read(length).decode("utf-8") if length > 0 else "{}"
        payload = AnalyzeSkillRequest.from_dict(json.loads(raw_body))
        execution_id = uuid.uuid4().hex
        task_store.create(execution_id, request={
            "skill_path": payload.skill_path,
            "input_payload": payload.input_payload,
            "timeout_seconds": payload.timeout_seconds,
            "network_policy": payload.network_policy,
            "analysis_mode": payload.analysis_mode,
            "llm_config": payload.llm_config.to_public_dict(),
        })
        task_request = {
            "skill_path": payload.skill_path,
            "input_payload": payload.input_payload,
            "timeout_seconds": payload.timeout_seconds,
            "network_policy": payload.network_policy,
            "analysis_mode": payload.analysis_mode,
            "llm_config": payload.llm_config.to_public_dict(),
        }
        log_writer.write(
            execution_id=execution_id,
            status="running",
            request=task_request,
        )

        if payload.analysis_mode == "static_only":
            source_dir, skill_file = resolve_skill_target(payload.skill_path)
            definition = load_skill_definition(
                source_dir,
                skill_file,
                allow_empty_actions=True,
            )
            report = analyze_static_skill(definition, analysis_mode=payload.analysis_mode)
            response = _build_static_response(
                execution_id=execution_id,
                payload=payload,
                source_dir=str(source_dir),
                skill_file=skill_file,
                report=report,
            )
            task_store.complete(execution_id, response.to_dict())
            log_writer.write(
                execution_id=execution_id,
                status="completed",
                request=task_request,
                result=response.to_dict(),
            )
            return _json_response(start_response, 200, response.to_dict())

        execution = runner.run(
            execution_id=execution_id,
            skill_path=payload.skill_path,
            input_payload=payload.input_payload,
            timeout_seconds=payload.timeout_seconds,
            network_policy=payload.network_policy,
            llm_config=payload.llm_config,
        )
        report = analyze_trace(execution, analysis_mode=payload.analysis_mode)
        telemetry_report = build_execution_report(execution)
        risk_profile = map_risk_profile(
            risk_score=report["risk_score"],
            detected_behaviors=report["detected_behaviors"],
        )
        response = AnalyzeSkillResponse(
            execution_id=execution_id,
            status="completed",
            skill_path=execution.skill_path,
            skill_file=execution.skill_file,
            sandbox_image=execution.sandbox_image,
            runtime_name=execution.runtime_name,
            network_policy=payload.network_policy,
            analysis_mode=payload.analysis_mode,
            llm_config=payload.llm_config.to_public_dict(),
            exit_code=execution.exit_code,
            timed_out=execution.timed_out,
            stdout=execution.stdout,
            stderr=execution.stderr,
            trace_summary=report["trace_summary"],
            risk_score=report["risk_score"],
            risk_level=risk_profile["risk_level"],
            risk_level_name=risk_profile["risk_level_name"],
            primary_risk=risk_profile["primary_risk"],
            risk_labels=risk_profile["risk_labels"],
            risk_summary=risk_profile["risk_summary"],
            detected_behaviors=report["detected_behaviors"],
            evidence_timeline=report["evidence_timeline"],
            file_events=telemetry_report["file_events"],
            network_events=telemetry_report["network_events"],
            process_events=telemetry_report["process_events"],
            tool_calls=telemetry_report["tool_calls"],
            llm_events=telemetry_report["llm_events"],
            data_flows=telemetry_report["data_flows"],
            normalized_events=telemetry_report.get("normalized_events", []),
            runtime_events_v2=report.get("runtime_events_v2", []),
            runtime_provenance_graph=report.get("runtime_provenance_graph", {}),
            runtime_chains=report.get("runtime_chains", []),
            runtime_coverage=report.get("runtime_coverage", {}),
            runtime_policy_violations=report.get("runtime_policy_violations", []),
            dynamic_analysis_summary=report.get("dynamic_analysis_summary", {}),
            taint_sources=report.get("taint_sources", []),
            resource_usage=execution.resource_usage.to_dict(),
            primary_chain=report.get("primary_chain", []),
            root_cause=report.get("root_cause", "unknown"),
            root_cause_detail=report.get("root_cause_detail", "unknown"),
            root_cause_v2=report.get("root_cause_v2", {}),
            graph_summary=report.get("graph_summary", {}),
            final_decision=report.get("final_decision", "unknown"),
            triggered_factors=report.get("triggered_factors", []),
            suppression_factors=report.get("suppression_factors", []),
            decision_evidence=report.get("decision_evidence", {}),
            capability_profile=report.get("capability_profile", {}),
            capability_tags=report.get("capability_tags", []),
            recommended_execution_profile=report.get("recommended_execution_profile", ""),
            recommended_trigger_mode=report.get("recommended_trigger_mode", ""),
            estimated_budget_class=report.get("estimated_budget_class", ""),
            execution_feasibility=report.get("execution_feasibility", ""),
            blocking_requirements=report.get("blocking_requirements", []),
            enabled_adapters=report.get("enabled_adapters", []),
            adapter_events_summary=report.get("adapter_events_summary", {}),
            synthetic_artifact_summary=report.get("synthetic_artifact_summary", {}),
            trigger_plan=report.get("trigger_plan", {}),
            trigger_used=report.get("trigger_used", []),
            trigger_hits=report.get("trigger_hits", []),
            trigger_unexecuted=report.get("trigger_unexecuted", []),
            trigger_events_summary=report.get("trigger_events_summary", {}),
            severity_label=report.get("severity_label", ""),
            evidence_strength=report.get("evidence_strength", ""),
            decision_rationale=report.get("decision_rationale", {}),
            dynamic_chain_observed=report.get("dynamic_chain_observed", False),
            instruction_chain_recovered=report.get("instruction_chain_recovered", False),
            chain_evidence_type=report.get("chain_evidence_type", "none"),
            instruction_chain=report.get("instruction_chain", []),
            instruction_indicators=report.get("instruction_indicators", []),
            static_supply_chain_risk=report.get("static_supply_chain_risk", {}),
            instruction_document_scan=report.get("instruction_document_scan", {}),
            instruction_actions=report.get("instruction_actions", []),
            instruction_entities=report.get("instruction_entities", []),
            instruction_graph=report.get("instruction_graph", {}),
            validated_instruction_paths=report.get("validated_instruction_paths", []),
            partial_instruction_paths=report.get("partial_instruction_paths", []),
            instruction_analysis_summary=report.get("instruction_analysis_summary", {}),
            extraction_coverage=report.get("extraction_coverage", {}),
            abstention_reasons=report.get("abstention_reasons", []),
            static_artifacts_v2=report.get("static_artifacts_v2", []),
            static_semantic_units=report.get("static_semantic_units", []),
            deterministic_mentions=report.get("deterministic_mentions", []),
            extracted_actions=report.get("extracted_actions", []),
            grounding_validation=report.get("grounding_validation", []),
            resolved_entities=report.get("resolved_entities", []),
            entity_resolutions=report.get("entity_resolutions", []),
            instruction_provenance_graph=report.get("instruction_provenance_graph", {}),
            static_chains=report.get("static_chains", []),
            static_coverage=report.get("static_coverage", {}),
            static_analysis_summary=report.get("static_analysis_summary", {}),
            llm_extraction_metadata=report.get("llm_extraction_metadata", []),
            static_schema_version=report.get("static_schema_version", ""),
            schema_version=report.get("schema_version", ""),
            final_risk_level=report.get("final_risk_level", ""),
            final_label_reason=report.get("final_label_reason", ""),
        )
        task_store.complete(execution_id, response.to_dict())
        log_writer.write(
            execution_id=execution_id,
            status="completed",
            request=task_request,
            result=response.to_dict(),
        )
        return _json_response(start_response, 200, response.to_dict())
    except json.JSONDecodeError as exc:
        return _json_response(start_response, 400, {"error": f"Invalid JSON: {exc}"})
    except ValueError as exc:
        return _json_response(start_response, 400, {"error": str(exc)})
    except DockerUnavailableError as exc:
        return _json_response(start_response, 503, {"error": str(exc)})
    except SandboxRunError as exc:
        if "execution_id" in locals():
            task_store.fail(execution_id, str(exc))
            log_writer.write(
                execution_id=execution_id,
                status="failed",
                request=task_request if "task_request" in locals() else {},
                error=str(exc),
            )
        return _json_response(start_response, 400, {"error": str(exc)})
    except Exception as exc:  # pragma: no cover - defensive fallback
        if "execution_id" in locals():
            task_store.fail(execution_id, f"Unexpected sandbox failure: {exc}")
            log_writer.write(
                execution_id=execution_id,
                status="failed",
                request=task_request if "task_request" in locals() else {},
                error=f"Unexpected sandbox failure: {exc}",
            )
        return _json_response(start_response, 500, {"error": f"Unexpected sandbox failure: {exc}"})


def _handle_get_task(path: str, start_response):
    execution_id = path.rsplit("/", 1)[-1]
    task = task_store.get(execution_id)
    if task is None:
        return _json_response(start_response, 404, {"error": "Task not found"})
    payload = TaskResponse(
        execution_id=task.execution_id,
        status=task.status,
        created_at=task.created_at,
        updated_at=task.updated_at,
        request=task.request,
        result=task.result,
        error=task.error,
    )
    return _json_response(start_response, 200, payload.to_dict())


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


def _build_static_response(
    execution_id: str,
    payload: AnalyzeSkillRequest,
    source_dir: str,
    skill_file: str,
    report: dict,
) -> AnalyzeSkillResponse:
    artifacts_dir = Path("artifacts/runs") / execution_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    (artifacts_dir / "normalized-events.jsonl").write_text("", encoding="utf-8")
    (artifacts_dir / "attack-chain.json").write_text(
        json.dumps(report.get("primary_chain", []), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (artifacts_dir / "epg.json").write_text(
        json.dumps(report.get("graph_export", {
            "execution_id": execution_id,
            "nodes": [],
            "edges": [],
            "summary": report.get("graph_summary", {}),
        }), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (artifacts_dir / "static-analysis.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=_json_default),
        encoding="utf-8",
    )
    risk_profile = map_risk_profile(
        risk_score=report["risk_score"],
        detected_behaviors=report["detected_behaviors"],
    )
    return AnalyzeSkillResponse(
        execution_id=execution_id,
        status="completed",
        skill_path=source_dir,
        skill_file=skill_file,
        sandbox_image="static-only",
        runtime_name="static-analysis",
        network_policy=payload.network_policy,
        analysis_mode=payload.analysis_mode,
        llm_config=payload.llm_config.to_public_dict(),
        exit_code=None,
        timed_out=False,
        stdout="",
        stderr="",
        trace_summary=report["trace_summary"],
        risk_score=report["risk_score"],
        risk_level=risk_profile["risk_level"],
        risk_level_name=risk_profile["risk_level_name"],
        primary_risk=risk_profile["primary_risk"],
        risk_labels=risk_profile["risk_labels"],
        risk_summary=risk_profile["risk_summary"],
        detected_behaviors=report["detected_behaviors"],
        evidence_timeline=report["evidence_timeline"],
        file_events=[],
        network_events=[],
        process_events=[],
        tool_calls=[],
        llm_events=[],
        data_flows=[],
        resource_usage={},
        normalized_events=[],
        runtime_events_v2=[],
        runtime_provenance_graph={},
        runtime_chains=[],
        runtime_coverage={},
        runtime_policy_violations=[],
        dynamic_analysis_summary={},
        taint_sources=[],
        primary_chain=report.get("primary_chain", []),
        root_cause=report.get("root_cause", "unknown"),
        root_cause_detail=report.get("root_cause_detail", "unknown"),
        root_cause_v2=report.get("root_cause_v2", {}),
        graph_summary=report.get("graph_summary", {}),
        final_decision=report.get("final_decision", "unknown"),
        triggered_factors=report.get("triggered_factors", []),
        suppression_factors=report.get("suppression_factors", []),
        decision_evidence=report.get("decision_evidence", {}),
        capability_profile=report.get("capability_profile", {}),
        capability_tags=report.get("capability_tags", []),
        recommended_execution_profile=report.get("recommended_execution_profile", ""),
        recommended_trigger_mode=report.get("recommended_trigger_mode", ""),
        estimated_budget_class=report.get("estimated_budget_class", ""),
        execution_feasibility=report.get("execution_feasibility", ""),
        blocking_requirements=report.get("blocking_requirements", []),
        enabled_adapters=report.get("enabled_adapters", []),
        adapter_events_summary=report.get("adapter_events_summary", {}),
        synthetic_artifact_summary=report.get("synthetic_artifact_summary", {}),
        trigger_plan=report.get("trigger_plan", {}),
        trigger_used=report.get("trigger_used", []),
        trigger_hits=report.get("trigger_hits", []),
        trigger_unexecuted=report.get("trigger_unexecuted", []),
        trigger_events_summary=report.get("trigger_events_summary", {}),
        severity_label=report.get("severity_label", ""),
        evidence_strength=report.get("evidence_strength", ""),
        decision_rationale=report.get("decision_rationale", {}),
        dynamic_chain_observed=report.get("dynamic_chain_observed", False),
        instruction_chain_recovered=report.get("instruction_chain_recovered", False),
        chain_evidence_type=report.get("chain_evidence_type", "none"),
        instruction_chain=report.get("instruction_chain", []),
        instruction_indicators=report.get("instruction_indicators", []),
        static_supply_chain_risk=report.get("static_supply_chain_risk", {}),
        instruction_document_scan=report.get("instruction_document_scan", {}),
        instruction_actions=report.get("instruction_actions", []),
        instruction_entities=report.get("instruction_entities", []),
        instruction_graph=report.get("instruction_graph", {}),
        validated_instruction_paths=report.get("validated_instruction_paths", []),
        partial_instruction_paths=report.get("partial_instruction_paths", []),
        instruction_analysis_summary=report.get("instruction_analysis_summary", {}),
        extraction_coverage=report.get("extraction_coverage", {}),
        abstention_reasons=report.get("abstention_reasons", []),
        static_artifacts_v2=report.get("static_artifacts_v2", []),
        static_semantic_units=report.get("static_semantic_units", []),
        deterministic_mentions=report.get("deterministic_mentions", []),
        extracted_actions=report.get("extracted_actions", []),
        grounding_validation=report.get("grounding_validation", []),
        resolved_entities=report.get("resolved_entities", []),
        entity_resolutions=report.get("entity_resolutions", []),
        instruction_provenance_graph=report.get("instruction_provenance_graph", {}),
        static_chains=report.get("static_chains", []),
        static_coverage=report.get("static_coverage", {}),
        static_analysis_summary=report.get("static_analysis_summary", {}),
        llm_extraction_metadata=report.get("llm_extraction_metadata", []),
        static_schema_version=report.get("static_schema_version", ""),
        schema_version=report.get("schema_version", ""),
        final_risk_level=report.get("final_risk_level", ""),
        final_label_reason=report.get("final_label_reason", ""),
    )


def _json_default(value):
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
