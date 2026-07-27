from __future__ import annotations

import re

from app.static.artifact_schema import SemanticUnit
from app.static.dataflow.propagation_schema import FlowBuilder, FlowExtractionResult


ASSIGN_CAT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=\$?\((?:cat|base64)\s+([^)]+)\)")
ASSIGN_ENV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=\"?\$[{]?([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?[}]?\"?")
URL_RE = re.compile(r"https?://[^\s\"']+")
VAR_RE = re.compile(r"\$[{]?([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?[}]?")


class ShellFlowAnalyzer:
    def analyze(self, units: list[SemanticUnit], mention_base: int, action_base: int) -> FlowExtractionResult:
        builder = FlowBuilder(mention_base, action_base)
        tainted_vars: dict[str, set[str]] = {}
        file_vars: dict[str, str] = {}
        downloads: dict[str, str] = {}
        archive_downloads: dict[str, str] = {}
        for unit in sorted(units, key=lambda item: (item.artifact_id, item.start_line)):
            rel = str(unit.metadata.get("relative_path", ""))
            if unit.metadata.get("language") not in {"shell", "bash", "zsh", "dockerfile", "makefile"} and not rel.endswith((".sh", ".bash", ".zsh")):
                continue
            text = unit.text.strip()
            if not text:
                continue
            self._handle_assignment(unit, text, builder, tainted_vars, file_vars)
            self._handle_pipe(unit, text, builder)
            self._handle_curl(unit, text, builder, tainted_vars, file_vars, downloads, archive_downloads)
            self._handle_execute(unit, text, builder, downloads, archive_downloads)
            self._handle_persistence_and_abuse(unit, text, builder)
        return builder.result()

    def _handle_assignment(self, unit: SemanticUnit, text: str, builder: FlowBuilder, tainted_vars: dict[str, set[str]], file_vars: dict[str, str]) -> None:
        match = ASSIGN_CAT_RE.search(text)
        if match:
            var, path = match.group(1), match.group(2).strip().strip("\"'")
            source = builder.mention(unit, "file_path", path, extractor="shell_cat_source")
            builder.action(unit, "READ", object_mentions=[source], raw_verb="cat", metadata={"flow_role": "source"})
            tainted_vars[var] = {source}
            file_vars[var] = path
            return
        match = ASSIGN_ENV_RE.search(text)
        if match:
            var, env_name = match.group(1), match.group(2)
            source = builder.mention(unit, "environment_variable", env_name, extractor="shell_env_source")
            builder.action(unit, "READ", object_mentions=[source], raw_verb="env", metadata={"flow_role": "source"})
            builder.action(unit, "ACCESS_CREDENTIAL", object_mentions=[source], raw_verb="env", metadata={"flow_role": "source"})
            tainted_vars[var] = {source}

    def _handle_pipe(self, unit: SemanticUnit, text: str, builder: FlowBuilder) -> None:
        if "|" not in text or "curl" not in text:
            return
        if re.search(r"\bcat\s+([^\s|]+)\s*\|\s*curl\b.*(?:--data-binary|-d)\s+@-", text):
            path = re.search(r"\bcat\s+([^\s|]+)", text).group(1).strip("\"'")
            source = builder.mention(unit, "file_path", path, extractor="shell_pipe_source")
            url = _first_url(text)
            dest = builder.mention(unit, "url", url, extractor="shell_pipe_sink") if url else None
            builder.action(unit, "READ", object_mentions=[source], raw_verb="cat", metadata={"flow_role": "source"})
            builder.action(unit, "SEND", object_mentions=[source], source_mentions=[source], destination_mentions=[dest] if dest else [], raw_verb="curl", metadata={"flow_role": "pipe_payload"})
        if re.search(r"\b(curl|wget)\b.*\|\s*(?:sudo\s+)?(?:sh|bash|python|python3)\b", text):
            url = _first_url(text)
            if url:
                dest = builder.mention(unit, "url", url, extractor="shell_pipe_download")
                builder.action(unit, "DOWNLOAD", object_mentions=[dest], source_mentions=[dest], raw_verb="curl", metadata={"flow_role": "download"})
                builder.action(unit, "EXECUTE", object_mentions=[dest], raw_verb="pipe_to_shell", metadata={"flow_role": "execute_downloaded_artifact"})

    def _handle_curl(
        self,
        unit: SemanticUnit,
        text: str,
        builder: FlowBuilder,
        tainted_vars: dict[str, set[str]],
        file_vars: dict[str, str],
        downloads: dict[str, str],
        archive_downloads: dict[str, str],
    ) -> None:
        if not re.search(r"\b(curl|wget)\b", text):
            return
        url = _first_url(text)
        url_id = builder.mention(unit, "url", url, extractor="shell_url") if url else None
        output = _curl_output_path(text)
        if url and output:
            file_id = builder.mention(unit, "file_path", output, extractor="shell_download_destination")
            builder.action(unit, "DOWNLOAD", object_mentions=[file_id], source_mentions=[url_id] if url_id else [], destination_mentions=[file_id], raw_verb="curl", metadata={"flow_role": "download"})
            downloads[output] = file_id
            if output.endswith((".zip", ".tar", ".tgz", ".gz")):
                archive_downloads[output] = file_id
        taints = _taints_in_text(text, tainted_vars)
        if taints and re.search(r"(\s-d\s|--data|--data-raw|--data-binary|-F\s|--form)", text):
            builder.action(unit, "SEND", object_mentions=sorted(taints), source_mentions=sorted(taints), destination_mentions=[url_id] if url_id else [], raw_verb="curl", metadata={"flow_role": "payload"})
        if taints and re.search(r"Authorization:|X-API-Key:", text, re.I):
            builder.action(unit, "INVOKE_API", object_mentions=sorted(taints), source_mentions=sorted(taints), destination_mentions=[url_id] if url_id else [], raw_verb="curl", metadata={"flow_role": "authentication"})
        upload_file = _curl_upload_file(text, file_vars)
        if upload_file and url_id:
            file_id = builder.mention(unit, "file_path", upload_file, extractor="shell_upload_file")
            builder.action(unit, "UPLOAD", object_mentions=[file_id], source_mentions=[file_id], destination_mentions=[url_id], raw_verb="curl", metadata={"flow_role": "file_upload"})

    def _handle_execute(self, unit: SemanticUnit, text: str, builder: FlowBuilder, downloads: dict[str, str], archive_downloads: dict[str, str]) -> None:
        for path, file_id in downloads.items():
            if re.search(rf"\b(?:bash|sh|python|python3|node)?\s*{re.escape(path)}\b", text) or text.strip() == path:
                builder.action(unit, "EXECUTE", object_mentions=[file_id], raw_verb="execute_downloaded", metadata={"flow_role": "execute_downloaded_artifact"})
        for archive in archive_downloads:
            if re.search(rf"\b(unzip|tar)\b.*{re.escape(archive)}", text):
                archive_id = downloads[archive]
                builder.action(unit, "EXTRACT", object_mentions=[archive_id], raw_verb="extract_archive", metadata={"flow_role": "archive_extract"})

    def _handle_persistence_and_abuse(self, unit: SemanticUnit, text: str, builder: FlowBuilder) -> None:
        lowered = text.lower()
        if any(token in lowered for token in {"crontab", "systemctl enable", "launchctl", "startup", ".claude/settings.json", "sessionstart"}):
            target = builder.mention(unit, "persistence_location", _persistence_label(text), extractor="shell_persistence")
            builder.action(unit, "PERSIST", object_mentions=[target], destination_mentions=[target], raw_verb="persist", metadata={"attack_template": "persistence"})
        if _reverse_shell(text):
            url = _first_url(text)
            dest = builder.mention(unit, "url", url, extractor="shell_reverse_shell") if url else None
            builder.action(unit, "EXECUTE", destination_mentions=[dest] if dest else [], raw_verb="reverse_shell", metadata={"attack_template": "reverse_shell"})
        if ":(){ :|:& };:" in text or re.search(r"\b(stress-ng|xmrig|minerd|while true; do .*curl)\b", text, re.I):
            builder.action(unit, "EXECUTE", raw_verb="resource_abuse", metadata={"attack_template": "resource_abuse"})


def _first_url(text: str) -> str | None:
    match = URL_RE.search(text)
    return match.group(0).rstrip(".,") if match else None


def _curl_output_path(text: str) -> str | None:
    match = re.search(r"(?:-o|-O|--output-document=|--output)\s*=?\s*([^\s]+)", text)
    if match:
        return match.group(1).strip("\"'")
    return None


def _taints_in_text(text: str, tainted_vars: dict[str, set[str]]) -> set[str]:
    taints: set[str] = set()
    for match in VAR_RE.finditer(text):
        taints.update(tainted_vars.get(match.group(1), set()))
    return taints


def _curl_upload_file(text: str, file_vars: dict[str, str]) -> str | None:
    match = re.search(r"(?:-F|--form)\s+[^\s=]+=@([^\s]+)|--data-binary\s+@([^\s]+)", text)
    if not match:
        return None
    raw = (match.group(1) or match.group(2)).strip("\"'")
    var = VAR_RE.fullmatch(raw)
    return file_vars.get(var.group(1), raw) if var else raw


def _persistence_label(text: str) -> str:
    lowered = text.lower()
    if "crontab" in lowered or "cron" in lowered:
        return "cron"
    if "systemctl" in lowered or "systemd" in lowered:
        return "systemd"
    if ".claude/settings.json" in lowered or "sessionstart" in lowered:
        return ".claude/settings.json"
    return "persistence_target"


def _reverse_shell(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in {"bash -i", "/bin/sh -i", "nc -e", "socat"}) and any(token in lowered for token in {"/dev/tcp", "dup2", "tcp:"})
