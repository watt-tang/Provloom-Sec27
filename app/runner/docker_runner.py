from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from shlex import quote

from app.runner.models import SandboxExecution
from app.runner.trace_parser import parse_trace_dir


class DockerUnavailableError(RuntimeError):
    pass


class SandboxRunError(RuntimeError):
    pass


class DockerRunner:
    def __init__(
        self,
        image_name: str = "skill-sandbox-mvp:latest",
        dockerfile_dir: str = "docker/sandbox",
    ) -> None:
        self.image_name = image_name
        self.dockerfile_dir = Path(dockerfile_dir)

    def run(self, skill_path: str, command: list[str], timeout_seconds: int) -> SandboxExecution:
        source_dir = Path(skill_path).expanduser().resolve()
        if not source_dir.exists() or not source_dir.is_dir():
            raise SandboxRunError(f"Skill path does not exist or is not a directory: {source_dir}")
        if not command:
            raise SandboxRunError("Command must not be empty.")

        self._ensure_docker_available()
        self._build_image()

        with tempfile.TemporaryDirectory(prefix="skill-sandbox-") as temp_dir:
            temp_root = Path(temp_dir)
            mounted_skill_dir = temp_root / "skill"
            artifacts_dir = temp_root / "artifacts"
            shutil.copytree(source_dir, mounted_skill_dir)
            artifacts_dir.mkdir(parents=True, exist_ok=True)

            runner_script = self._build_runner_script(command, timeout_seconds)
            container_name = f"skill-sandbox-{uuid.uuid4().hex[:10]}"

            docker_cmd = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "256m",
                "--cpus",
                "1.0",
                "--mount",
                f"type=bind,src={mounted_skill_dir},dst=/workspace/skill",
                "--mount",
                f"type=bind,src={artifacts_dir},dst=/artifacts",
                self.image_name,
                "sh",
                "-lc",
                runner_script,
            ]

            result = subprocess.run(
                docker_cmd,
                text=True,
                capture_output=True,
                check=False,
            )

            meta = self._load_meta(artifacts_dir / "meta.json")
            stdout = self._read_text(artifacts_dir / "stdout.log")
            stderr = self._read_text(artifacts_dir / "stderr.log")
            trace_artifacts = parse_trace_dir(artifacts_dir)

            if result.returncode != 0 and not meta:
                raise SandboxRunError(
                    "Docker run failed before analysis artifacts were generated. "
                    f"stderr={result.stderr.strip()}"
                )

            return SandboxExecution(
                skill_path=str(source_dir),
                sandbox_image=self.image_name,
                command=command,
                exit_code=meta.get("exit_code"),
                timed_out=bool(meta.get("timed_out", False)),
                stdout=stdout,
                stderr=stderr or result.stderr,
                trace_artifacts=trace_artifacts,
                artifacts_dir=str(artifacts_dir),
            )

    def _ensure_docker_available(self) -> None:
        if shutil.which("docker") is None:
            raise DockerUnavailableError(
                "Docker CLI is not available. Please install Docker and ensure `docker` is on PATH."
            )

    def _build_image(self) -> None:
        cmd = [
            "docker",
            "build",
            "-t",
            self.image_name,
            str(self.dockerfile_dir),
        ]
        result = subprocess.run(cmd, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            raise SandboxRunError(f"Failed to build sandbox image: {result.stderr.strip()}")

    def _build_runner_script(self, command: list[str], timeout_seconds: int) -> str:
        command_str = " ".join(quote(part) for part in command)
        return f"""
set -eu
cd /workspace/skill
TIMED_OUT=0
EXIT_CODE=0
if timeout --preserve-status {timeout_seconds}s sh -lc 'strace -ff -tt -s 256 -o /artifacts/trace.log -e trace=file,process,network {command_str} > /artifacts/stdout.log 2> /artifacts/stderr.log'; then
  EXIT_CODE=0
else
  EXIT_CODE=$?
  if [ "$EXIT_CODE" = "124" ]; then
    TIMED_OUT=1
  fi
fi
printf '{{"exit_code": %s, "timed_out": %s}}' "$EXIT_CODE" "$TIMED_OUT" > /artifacts/meta.json
exit 0
""".strip()

    @staticmethod
    def _load_meta(path: Path) -> dict:
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _read_text(path: Path) -> str:
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
