from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.analyzer.rules import analyze_trace
from app.backend.log_writer import ExecutionLogWriter
from app.backend.schemas import (
    AnalyzeSkillResponse,
    DEFAULT_LLM_PROVIDER,
    LLMConfig,
    default_llm_api_key,
    default_llm_base_url,
    default_llm_model,
    normalize_llm_provider,
)
from app.reporting.risk_mapper import map_risk_profile
from app.runner.docker_runner import DockerRunner
from app.telemetry.collector import build_execution_report


def build_response(
    execution_id: str,
    skill_path: str,
    network_policy: str,
    llm_config: LLMConfig,
    execution,
) -> dict:
    report = analyze_trace(execution)
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
        network_policy=network_policy,
        analysis_mode="rule_plus_epg",
        llm_config=llm_config.to_public_dict(),
        llm_model_name=execution.llm_model_name,
        llm_token_usage=dict(execution.llm_token_usage or {}),
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
        resource_usage=execution.resource_usage.to_dict(),
    )
    return response.to_dict()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SiliconFlow-backed sandbox smoke tests and write JSON logs.")
    parser.add_argument("--provider", default=DEFAULT_LLM_PROVIDER)
    parser.add_argument("--api-key", default=os.getenv("PROVLOOM_SCAN_API_KEY", default_llm_api_key(DEFAULT_LLM_PROVIDER)))
    parser.add_argument("--base-url", default=default_llm_base_url(DEFAULT_LLM_PROVIDER))
    parser.add_argument("--model", default=default_llm_model(DEFAULT_LLM_PROVIDER))
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()

    repo_root = REPO_ROOT
    runner = DockerRunner()
    log_writer = ExecutionLogWriter(log_dir=str(repo_root / "Log"))
    provider = normalize_llm_provider(args.provider)
    llm_config = LLMConfig(
        enabled=True,
        provider=provider,
        base_url=args.base_url,
        api_key=args.api_key,
        model=args.model,
        temperature=0.0,
        max_steps=16,
    )

    test_cases = [
        {
            "name": "deepseek_demo",
            "skill_path": str(repo_root / "examples/skills/deepseek_skill_demo"),
            "input_payload": {
                "message": "run deepseek demo and leave observable file, process, and network traces",
            },
            "timeout_seconds": args.timeout_seconds,
            "network_policy": "default",
        },
        {
            "name": "user_test_skill",
            "skill_path": str(repo_root / "test"),
            "input_payload": {
                "task": "根据 SKILL.md 的说明尝试执行一次最小真实工作流。如果依赖缺失，请显式验证、记录失败原因，并把结论写入工作区文件。",
                "query": "上海周末咖啡店推荐",
                "city": "上海",
            },
            "timeout_seconds": args.timeout_seconds,
            "network_policy": "default",
        },
    ]

    summaries: list[dict[str, object]] = []
    for case in test_cases:
        execution_id = uuid.uuid4().hex
        request_payload = {
            "skill_path": case["skill_path"],
            "input_payload": case["input_payload"],
            "timeout_seconds": case["timeout_seconds"],
            "network_policy": case["network_policy"],
            "llm_config": llm_config.to_public_dict(),
            "suite_case": case["name"],
        }
        log_writer.write(
            execution_id=execution_id,
            status="running",
            request=request_payload,
        )
        try:
            execution = runner.run(
                execution_id=execution_id,
                skill_path=case["skill_path"],
                input_payload=case["input_payload"],
                timeout_seconds=case["timeout_seconds"],
                network_policy=case["network_policy"],
                llm_config=llm_config,
            )
            response = build_response(
                execution_id=execution_id,
                skill_path=case["skill_path"],
                network_policy=case["network_policy"],
                llm_config=llm_config,
                execution=execution,
            )
            log_writer.write(
                execution_id=execution_id,
                status="completed",
                request=request_payload,
                result=response,
            )
            log_path = log_writer.get_log_path(execution_id, request_payload)
            summaries.append(
                {
                    "case": case["name"],
                    "execution_id": execution_id,
                    "status": "completed",
                    "risk_score": response["risk_score"],
                    "detected_behaviors": response["detected_behaviors"],
                    "log_file": str(log_path),
                }
            )
        except Exception as exc:
            message = str(exc)
            log_writer.write(
                execution_id=execution_id,
                status="failed",
                request=request_payload,
                error=message,
            )
            log_path = log_writer.get_log_path(execution_id, request_payload)
            summaries.append(
                {
                    "case": case["name"],
                    "execution_id": execution_id,
                    "status": "failed",
                    "error": message,
                    "log_file": str(log_path),
                }
            )

    print(json.dumps({"suite": "deepseek", "results": summaries}, ensure_ascii=False, indent=2))
    return 0 if all(item["status"] == "completed" for item in summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
