from __future__ import annotations

import csv
import shutil
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_CSV = PROJECT_ROOT / "docs" / "human_complete670.csv"
OUTPUT_DIR = Path("/mnt/e/humanreview")
MANIFEST_CSV = OUTPUT_DIR / "manifest.csv"


def windows_to_posix(raw: str) -> str:
    return raw.replace("\\", "/").replace("E:", "/mnt/e")


def iter_candidate_paths(row: dict[str, str]) -> Iterable[Path]:
    raw_candidates = [
        row.get("provloom_selected_skill_root", ""),
        row.get("skillscan_path", ""),
        row.get("sample_root_or_path", ""),
        row.get("cisco_source_path", ""),
        row.get("clawvet_source_path", ""),
        row.get("skillfortify_source_path", ""),
    ]
    seen = set()
    for raw in raw_candidates:
        if not raw:
            continue
        normalized = windows_to_posix(raw.strip())
        if normalized in seen:
            continue
        seen.add(normalized)
        yield Path(normalized)


def choose_markdown_from_dir(path: Path) -> tuple[Path | None, str]:
    direct_skill = path / "SKILL.md"
    if direct_skill.exists():
        return direct_skill, "direct_skill"

    direct_readmes = sorted(path.glob("README*.md")) + sorted(path.glob("readme*.md"))
    if direct_readmes:
        return direct_readmes[0], "direct_readme"

    top_level_md = sorted(
        p
        for p in path.glob("*.md")
        if p.name.lower() not in {"license.md", "changelog.md", "contributing.md", "code_of_conduct.md"}
    )
    if top_level_md:
        preferred = sorted(top_level_md, key=lambda p: (0 if "readme" in p.name.lower() else 1, p.name.lower()))[0]
        return preferred, "top_level_md"

    nested_skill = sorted(path.rglob("SKILL.md"))
    if nested_skill:
        return nested_skill[0], "nested_skill"

    nested_readme = sorted(path.rglob("README*.md")) + sorted(path.rglob("readme*.md"))
    if nested_readme:
        return nested_readme[0], "nested_readme"

    nested_md = sorted(
        p
        for p in path.rglob("*.md")
        if p.name.lower() not in {"license.md", "changelog.md", "contributing.md", "code_of_conduct.md"}
    )
    if nested_md:
        return nested_md[0], "nested_md"

    return None, "missing"


def choose_source_markdown(row: dict[str, str]) -> tuple[Path | None, str, str]:
    for candidate in iter_candidate_paths(row):
        if candidate.is_file() and candidate.suffix.lower() == ".md":
            return candidate, "direct_file", str(candidate)
        if candidate.is_dir():
            chosen, strategy = choose_markdown_from_dir(candidate)
            if chosen is not None:
                return chosen, strategy, str(candidate)
    return None, "missing", ""


def render_placeholder(row_index: int, row: dict[str, str]) -> str:
    return "\n".join(
        [
            f"<!-- export_index: {row_index:03d} -->",
            f"<!-- corpus: {row.get('corpus', '')} -->",
            f"<!-- sample_key: {row.get('sample_key', '')} -->",
            "<!-- source_markdown: MISSING -->",
            "",
            f"# {row.get('sample_name') or row.get('sample_key') or 'Unknown Sample'}",
            "",
            "No Markdown source file could be resolved automatically for this row.",
            "",
            "Reference fields:",
            f"- `sample_root_or_path`: {row.get('sample_root_or_path', '')}",
            f"- `provloom_selected_skill_root`: {row.get('provloom_selected_skill_root', '')}",
            f"- `skillscan_path`: {row.get('skillscan_path', '')}",
            "",
        ]
    )


def build_output_text(row_index: int, row: dict[str, str], source_md: Path | None, strategy: str, source_base: str) -> str:
    if source_md is None:
        return render_placeholder(row_index, row)
    body = source_md.read_text(encoding="utf-8", errors="replace")
    header = "\n".join(
        [
            f"<!-- export_index: {row_index:03d} -->",
            f"<!-- corpus: {row.get('corpus', '')} -->",
            f"<!-- sample_key: {row.get('sample_key', '')} -->",
            f"<!-- sample_name: {row.get('sample_name', '')} -->",
            f"<!-- resolution_strategy: {strategy} -->",
            f"<!-- source_base: {source_base} -->",
            f"<!-- source_markdown: {source_md} -->",
            "",
        ]
    )
    return header + body


def main() -> None:
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    manifest_rows: list[dict[str, str]] = []
    with INPUT_CSV.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            source_md, strategy, source_base = choose_source_markdown(row)
            out_name = f"{index:03d}_SKILL.md"
            out_path = OUTPUT_DIR / out_name
            out_path.write_text(build_output_text(index, row, source_md, strategy, source_base), encoding="utf-8")
            manifest_rows.append(
                {
                    "index": str(index),
                    "output_file": str(out_path),
                    "corpus": row.get("corpus", ""),
                    "sample_key": row.get("sample_key", ""),
                    "sample_name": row.get("sample_name", ""),
                    "resolution_strategy": strategy,
                    "source_base": source_base,
                    "source_markdown": str(source_md) if source_md else "",
                }
            )

    with MANIFEST_CSV.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "index",
                "output_file",
                "corpus",
                "sample_key",
                "sample_name",
                "resolution_strategy",
                "source_base",
                "source_markdown",
            ],
        )
        writer.writeheader()
        writer.writerows(manifest_rows)

    print(f"Wrote {len(manifest_rows)} markdown files to {OUTPUT_DIR}")
    print(f"Wrote manifest to {MANIFEST_CSV}")


if __name__ == "__main__":
    main()
