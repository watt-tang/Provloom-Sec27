from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and optionally run a held-out Static deterministic split.")
    parser.add_argument("--malicious-root", required=True)
    parser.add_argument("--benign-root", required=True)
    parser.add_argument("--dev-malicious-paths", default="artifacts/malskillbench_static_100/sample_paths.txt")
    parser.add_argument("--dev-benign-paths", default="artifacts/malskillbench_static_100_benign/sample_paths.txt")
    parser.add_argument("--sample-size", type=int, default=500)
    parser.add_argument("--seed", type=int, default=20260721)
    parser.add_argument("--manifest", default="artifacts/static_heldout_500/manifest.json")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output-dir", default="artifacts/static_heldout_500")
    args = parser.parse_args()

    malicious = _sample(args.malicious_root, args.dev_malicious_paths, args.sample_size, args.seed)
    benign = _sample(args.benign_root, args.dev_benign_paths, args.sample_size, args.seed + 1)
    manifest = {
        "seed": args.seed,
        "sample_size_per_class": args.sample_size,
        "malicious_root": str(Path(args.malicious_root).resolve()),
        "benign_root": str(Path(args.benign_root).resolve()),
        "malicious_paths": malicious,
        "benign_paths": benign,
        "dev_exclusion_files": [args.dev_malicious_paths, args.dev_benign_paths],
        "note": "Do not tune rules on this held-out split and continue calling it held-out.",
    }
    manifest_path = Path(args.manifest)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    mal_txt = manifest_path.parent / "malicious_paths.txt"
    ben_txt = manifest_path.parent / "benign_paths.txt"
    mal_txt.write_text("\n".join(malicious) + "\n", encoding="utf-8")
    ben_txt.write_text("\n".join(benign) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "malicious": len(malicious), "benign": len(benign), "seed": args.seed}, ensure_ascii=False, indent=2))
    if args.run:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts/evaluate_static_deterministic.py"),
            "--malicious-paths",
            str(mal_txt),
            "--benign-paths",
            str(ben_txt),
            "--output-json",
            str(out_dir / "report.json"),
            "--output-md",
            str(out_dir / "report.md"),
        ]
        return subprocess.call(cmd, cwd=PROJECT_ROOT)
    return 0


def _sample(root: str, dev_paths_file: str, sample_size: int, seed: int) -> list[str]:
    root_path = Path(root).absolute()
    dev_paths: set[str] = set()
    dev_names: set[str] = set()
    for line in Path(dev_paths_file).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        candidate = Path(line.strip())
        dev_names.add(candidate.name)
        if candidate.exists():
            dev_paths.add(str(candidate.absolute()))
    candidates = _find_skill_dirs(root_path)
    candidates = [path for path in candidates if path not in dev_paths and Path(path).name not in dev_names]
    if len(candidates) < sample_size:
        raise SystemExit(f"not enough held-out candidates under {root}: requested {sample_size}, found {len(candidates)} after dev exclusion")
    rng = random.Random(seed)
    return sorted(rng.sample(candidates, sample_size))


def _find_skill_dirs(root_path: Path) -> list[str]:
    direct: list[str] = []
    with os.scandir(root_path) as entries:
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            skill_file = os.path.join(entry.path, "SKILL.md")
            if os.path.isfile(skill_file):
                direct.append(str(Path(entry.path).absolute()))
    if direct:
        return sorted(direct)

    candidates: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [name for name in dirnames if name not in {".git", "node_modules", "dist", "build", "vendor"}]
        if "SKILL.md" in filenames:
            candidates.append(str(Path(dirpath).absolute()))
    return sorted(candidates)


if __name__ == "__main__":
    raise SystemExit(main())
