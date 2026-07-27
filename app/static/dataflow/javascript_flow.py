from __future__ import annotations

import re

from app.static.artifact_schema import SemanticUnit
from app.static.dataflow.propagation_schema import FlowBuilder, FlowExtractionResult


ENV_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\.env\.([A-Za-z_][A-Za-z0-9_]*)")
FILE_ASSIGN_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:fs\.readFileSync|await\s+fs\.promises\.readFile)\(([^,)]+)")
URL_RE = re.compile(r"https?://[^\s\"'`)]+")


class JavaScriptFlowAnalyzer:
    def analyze(self, units: list[SemanticUnit], mention_base: int, action_base: int) -> FlowExtractionResult:
        builder = FlowBuilder(mention_base, action_base)
        tainted_vars: dict[str, set[str]] = {}
        file_vars: dict[str, str] = {}
        url_vars: dict[str, str] = {}
        for unit in sorted(units, key=lambda item: (item.artifact_id, item.start_line)):
            rel = str(unit.metadata.get("relative_path", ""))
            if unit.metadata.get("language") not in {"javascript", "typescript"} and not rel.endswith((".js", ".ts")):
                continue
            text = unit.text.strip()
            if not text:
                continue
            self._handle_sources(unit, text, builder, tainted_vars, file_vars, url_vars)
            self._handle_sinks(unit, text, builder, tainted_vars, file_vars, url_vars)
            self._handle_execution(unit, text, builder)
        return builder.result()

    def _handle_sources(
        self,
        unit: SemanticUnit,
        text: str,
        builder: FlowBuilder,
        tainted_vars: dict[str, set[str]],
        file_vars: dict[str, str],
        url_vars: dict[str, str],
    ) -> None:
        for match in ENV_ASSIGN_RE.finditer(text):
            var, env_name = match.group(1), match.group(2)
            source = builder.mention(unit, "environment_variable", env_name, extractor="js_env_source")
            builder.action(unit, "READ", object_mentions=[source], raw_verb="process.env", metadata={"flow_role": "source"})
            builder.action(unit, "ACCESS_CREDENTIAL", object_mentions=[source], raw_verb="process.env", metadata={"flow_role": "source"})
            tainted_vars[var] = {source}
        for match in FILE_ASSIGN_RE.finditer(text):
            var, raw_path = match.group(1), match.group(2).strip().strip("\"'")
            source = builder.mention(unit, "file_path", raw_path, extractor="js_file_source")
            builder.action(unit, "READ", object_mentions=[source], raw_verb="fs.readFile", metadata={"flow_role": "source"})
            tainted_vars[var] = {source}
            file_vars[var] = raw_path
        for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['\"](https?://[^'\"]+)['\"]", text):
            url_vars[match.group(1)] = match.group(2)
        for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:JSON\.stringify\()?(.+)", text):
            var, expr = match.group(1), match.group(2)
            taints = _taints(expr, tainted_vars)
            if taints:
                tainted_vars[var] = taints

    def _handle_sinks(
        self,
        unit: SemanticUnit,
        text: str,
        builder: FlowBuilder,
        tainted_vars: dict[str, set[str]],
        file_vars: dict[str, str],
        url_vars: dict[str, str],
    ) -> None:
        if "fetch(" in text or "axios." in text:
            url = _url_for_call(text, url_vars)
            dest = builder.mention(unit, "url", url, extractor="js_http_sink") if url else None
            taints = _taints(text, tainted_vars)
            if not taints:
                return
            if re.search(r"Authorization\s*:", text, re.I) and not re.search(r"\b(body|data|json|payload)\b", text, re.I):
                builder.action(unit, "INVOKE_API", object_mentions=sorted(taints), source_mentions=sorted(taints), destination_mentions=[dest] if dest else [], raw_verb="invoke_api", metadata={"flow_role": "authentication"})
            else:
                builder.action(unit, "SEND", object_mentions=sorted(taints), source_mentions=sorted(taints), destination_mentions=[dest] if dest else [], raw_verb="send", metadata={"flow_role": "payload"})
        if "FormData" in text or ".append(" in text:
            upload_path = next(iter(file_vars.values()), "")
            if upload_path:
                file_id = builder.mention(unit, "file_path", upload_path, extractor="js_form_upload")
                url = _url_for_call(text, url_vars)
                dest = builder.mention(unit, "url", url, extractor="js_form_upload_sink") if url else None
                builder.action(unit, "UPLOAD", object_mentions=[file_id], source_mentions=[file_id], destination_mentions=[dest] if dest else [], raw_verb="FormData", metadata={"flow_role": "file_upload"})

    def _handle_execution(self, unit: SemanticUnit, text: str, builder: FlowBuilder) -> None:
        if re.search(r"\b(exec|execFile|spawn)\s*\(", text):
            builder.action(unit, "EXECUTE", raw_verb="child_process", metadata={"flow_role": "child_process"})


def _taints(text: str, tainted_vars: dict[str, set[str]]) -> set[str]:
    taints: set[str] = set()
    for var, mentions in tainted_vars.items():
        if re.search(rf"\b{re.escape(var)}\b", text):
            taints.update(mentions)
    return taints


def _url_for_call(text: str, url_vars: dict[str, str]) -> str | None:
    match = URL_RE.search(text)
    if match:
        return match.group(0)
    for var, url in url_vars.items():
        if re.search(rf"\b{re.escape(var)}\b", text):
            return url
    return None
