from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from app.static.artifact_schema import SemanticUnit
from app.static.dataflow.propagation_schema import FlowBuilder, FlowExtractionResult


MAX_PROPAGATION_ROUNDS = 4
MAX_CALL_DEPTH = 2


@dataclass
class ValueState:
    taints: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    auth_only: bool = False


class PythonFlowAnalyzer:
    def analyze(self, units: list[SemanticUnit], mention_base: int, action_base: int) -> FlowExtractionResult:
        builder = FlowBuilder(mention_base, action_base)
        by_artifact: dict[str, list[SemanticUnit]] = {}
        for unit in units:
            if unit.metadata.get("language") == "python" or str(unit.metadata.get("relative_path", "")).endswith(".py"):
                by_artifact.setdefault(unit.artifact_id, []).append(unit)
        for artifact_units in by_artifact.values():
            self._analyze_artifact(sorted(artifact_units, key=lambda item: item.start_line), builder)
        return builder.result()

    def _analyze_artifact(self, units: list[SemanticUnit], builder: FlowBuilder) -> None:
        source = "\n".join(unit.text.rstrip("\n") for unit in units)
        if not source.strip():
            return
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            builder.add_limitation(f"python_parse_failure:{exc.lineno}")
            return
        unit_for_line = {unit.start_line: unit for unit in units}
        fallback = units[0]
        analyzer = _PythonArtifactAnalyzer(builder, unit_for_line, fallback)
        analyzer.visit(tree)


class _PythonArtifactAnalyzer(ast.NodeVisitor):
    def __init__(self, builder: FlowBuilder, unit_for_line: dict[int, SemanticUnit], fallback: SemanticUnit) -> None:
        self.builder = builder
        self.unit_for_line = unit_for_line
        self.fallback = fallback
        self.env: dict[str, ValueState] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.function_returns: dict[str, ValueState] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions[node.name] = node
        self.function_returns[node.name] = self._summarize_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value = self._expr_state(node.value)
        for target in node.targets:
            for name in _target_names(target):
                self.env[name] = value
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            value = self._expr_state(node.value)
            for name in _target_names(node.target):
                self.env[name] = value
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._handle_sink_call(node)
        self.generic_visit(node)

    def _summarize_function(self, node: ast.FunctionDef) -> ValueState:
        local = _PythonArtifactAnalyzer(self.builder, self.unit_for_line, self.fallback)
        local.functions = self.functions
        for stmt in node.body[:20]:
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                return local._expr_state(stmt.value)
            local.visit(stmt)
        return ValueState()

    def _expr_state(self, node: ast.AST) -> ValueState:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value.startswith(("http://", "https://")):
                return ValueState(urls={node.value})
            return ValueState(files={node.value} if _looks_path(node.value) else set())
        if isinstance(node, ast.Name):
            return self.env.get(node.id, ValueState())
        if isinstance(node, ast.Call):
            source = self._source_call(node)
            if source is not None:
                return source
            fn = _call_name(node.func)
            if fn in self.function_returns:
                return self.function_returns[fn]
            return self._merge(*(self._expr_state(arg) for arg in node.args), *(self._expr_state(kw.value) for kw in node.keywords))
        if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            values = []
            if isinstance(node, ast.Dict):
                values = list(node.values)
            else:
                values = list(node.elts)
            return self._merge(*(self._expr_state(item) for item in values if item is not None))
        if isinstance(node, ast.JoinedStr):
            return self._merge(*(self._expr_state(item.value) for item in node.values if isinstance(item, ast.FormattedValue)))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._merge(self._expr_state(node.left), self._expr_state(node.right))
        if isinstance(node, ast.Subscript):
            if _call_name(node.value) == "os.environ":
                key = _slice_literal(node.slice)
                if key:
                    unit = self._unit(node)
                    mention = self.builder.mention(unit, "environment_variable", key, extractor="python_env_source")
                    self.builder.action(unit, "READ", object_mentions=[mention], raw_verb="os.environ", metadata={"flow_role": "source"})
                    self.builder.action(unit, "ACCESS_CREDENTIAL", object_mentions=[mention], raw_verb="os.environ", metadata={"flow_role": "source"})
                    return ValueState(taints={mention})
            return self._expr_state(node.value)
        if isinstance(node, ast.Attribute):
            return self._expr_state(node.value)
        return ValueState()

    def _source_call(self, node: ast.Call) -> ValueState | None:
        fn = _call_name(node.func)
        unit = self._unit(node)
        if fn in {"os.getenv", "os.environ.get"} and node.args and isinstance(node.args[0], ast.Constant):
            mention = self.builder.mention(unit, "environment_variable", str(node.args[0].value), extractor="python_env_source")
            self.builder.action(unit, "READ", object_mentions=[mention], raw_verb="os.getenv", metadata={"flow_role": "source"})
            self.builder.action(unit, "ACCESS_CREDENTIAL", object_mentions=[mention], raw_verb="os.getenv", metadata={"flow_role": "source"})
            return ValueState(taints={mention})
        if isinstance(node.func, ast.Attribute) and fn in {"read", "read_text", "read_bytes"}:
            path = _path_from_read_call(node.func)
            if path:
                mention = self.builder.mention(unit, "file_path", path, extractor="python_file_source")
                self.builder.action(unit, "READ", object_mentions=[mention], raw_verb=fn, metadata={"flow_role": "source"})
                return ValueState(taints={mention}, files={path})
        if fn in {"json.load", "yaml.safe_load"} and node.args:
            inner = self._expr_state(node.args[0])
            return inner
        if fn == "open" and node.args:
            path = _literal(node.args[0])
            if path:
                mention = self.builder.mention(unit, "file_path", path, extractor="python_open_source")
                self.builder.action(unit, "READ", object_mentions=[mention], raw_verb="open", metadata={"flow_role": "source"})
                return ValueState(taints={mention}, files={path})
        return None

    def _handle_sink_call(self, node: ast.Call) -> None:
        fn = _call_name(node.func)
        unit = self._unit(node)
        if fn in {"requests.post", "requests.put", "requests.request", "httpx.post", "httpx.put", "aiohttp.post"}:
            url_state = self._expr_state(node.args[0]) if node.args else ValueState()
            url = next(iter(url_state.urls), None) or _literal(node.args[0]) if node.args else None
            dest = self.builder.mention(unit, "url", url, extractor="python_http_sink") if url and str(url).startswith(("http://", "https://")) else None
            payload = self._merge(*(self._expr_state(kw.value) for kw in node.keywords if kw.arg in {"json", "data", "files", "body"}))
            headers = self._merge(*(self._expr_state(kw.value) for kw in node.keywords if kw.arg == "headers"))
            if payload.taints:
                self.builder.action(unit, "SEND", object_mentions=sorted(payload.taints), source_mentions=sorted(payload.taints), destination_mentions=[dest] if dest else [], raw_verb=fn, metadata={"flow_role": "payload"})
            elif headers.taints:
                self.builder.action(unit, "INVOKE_API", object_mentions=sorted(headers.taints), source_mentions=sorted(headers.taints), destination_mentions=[dest] if dest else [], raw_verb=fn, metadata={"flow_role": "authentication"})
        if fn in {"socket.send", "socket.sendall"} and node.args:
            payload = self._expr_state(node.args[0])
            if payload.taints:
                self.builder.action(unit, "SEND", object_mentions=sorted(payload.taints), source_mentions=sorted(payload.taints), raw_verb=fn, metadata={"flow_role": "socket_payload"})
        if fn in {"subprocess.run", "subprocess.Popen", "os.system"} and node.args:
            state = self._expr_state(node.args[0])
            if state.taints:
                dest = next((self.builder.mention(unit, "url", url, extractor="python_subprocess_sink") for url in state.urls), None)
                self.builder.action(unit, "SEND", object_mentions=sorted(state.taints), source_mentions=sorted(state.taints), destination_mentions=[dest] if dest else [], raw_verb=fn, metadata={"flow_role": "subprocess_payload"})
            text = _literal(node.args[0])
            if text and _reverse_shell_text(text):
                dest = _first_url(text)
                dest_id = self.builder.mention(unit, "url", dest, extractor="python_reverse_shell_endpoint") if dest else None
                self.builder.action(unit, "EXECUTE", destination_mentions=[dest_id] if dest_id else [], raw_verb=fn, metadata={"attack_template": "reverse_shell"})

    def _merge(self, *states: ValueState) -> ValueState:
        merged = ValueState()
        for state in states:
            merged.taints.update(state.taints)
            merged.urls.update(state.urls)
            merged.files.update(state.files)
            merged.auth_only = merged.auth_only or state.auth_only
        return merged

    def _unit(self, node: ast.AST) -> SemanticUnit:
        return self.unit_for_line.get(getattr(node, "lineno", -1), self.fallback)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ""


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for elt in node.elts for name in _target_names(elt)]
    return []


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.List):
        return " ".join(str(_literal(elt) or "") for elt in node.elts)
    return None


def _slice_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _path_from_read_call(func: ast.Attribute) -> str | None:
    value = func.value
    if isinstance(value, ast.Call) and _call_name(value.func) == "Path" and value.args:
        return _literal(value.args[0])
    if isinstance(value, ast.Call) and _call_name(value.func) == "open" and value.args:
        return _literal(value.args[0])
    return None


def _looks_path(value: str) -> bool:
    return "/" in value or value.startswith(".") or "." in value


def _first_url(text: str) -> str | None:
    for token in text.split():
        if token.startswith(("http://", "https://")):
            return token
    return None


def _reverse_shell_text(text: str) -> bool:
    lowered = text.lower()
    return ("bash -i" in lowered or "/bin/sh -i" in lowered or "nc -e" in lowered or "socat" in lowered) and any(token in lowered for token in {"dup2", "/dev/tcp", "socket"})
