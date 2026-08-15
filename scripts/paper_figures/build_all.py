"""Build all four evaluation figures from frozen artifact values only."""
from pathlib import Path
import runpy
from PIL import Image, ImageDraw
from figure_style import OUT, TEXT

HERE = Path(__file__).resolve().parent
SCRIPTS = ["fig3_provbench_landscape.py", "fig4_screening_adjudication.py", "fig5_ablation.py", "fig6_coverage_errors.py"]
AUDIT_NOTE = """# Figure data audit

- Figure 3(b): 579/316/199 are from `artifacts/paper_usenix/metrics.json` and
  `benchmark_methodology/distribution.json`. Counterfactual pairs are omitted:
  the frozen artifacts report 160 pairs, but only 142 pairs with >=2 formal
  samples (and 143 complete formal pairs), so pair/case units are not uniform.
- Figure 4(b): 62 corrected benign decisions are from
  `artifacts/paper_usenix/static_vs_full/analysis.json`.
- Figure 6(b): the plotted 103/3/1/0 taxonomy is the paper-level frozen
  diagnosis used in `artifacts/paper_usenix/root_cause_diagnosis/summary.md`.
  A second frozen file, `fn_taxonomy_v2/summary.json`, instead records
  103 authorization/trust, 2 target-reached/no-carrier, 1 execution, and
  1 environment/dependency. This discrepancy is preserved here and not
  silently reconciled.
"""

def main():
    (HERE / "figure_data_audit.md").write_text(AUDIT_NOTE, encoding="utf-8")
    for script in SCRIPTS:
        print(f"[BUILD] {script}"); runpy.run_path(str(HERE / script), run_name="__main__")
    pngs = [OUT / f.replace(".py", ".png") for f in SCRIPTS]
    thumbs = []
    for path in pngs:
        image = Image.open(path).convert("RGB")
        image.thumbnail((1000, 430))
        thumbs.append((path.stem, image.copy()))
    sheet = Image.new("RGB", (2040, 940), "white")
    draw = ImageDraw.Draw(sheet)
    for i, (name, image) in enumerate(thumbs):
        x = 20 + (i % 2) * 1010; y = 20 + (i // 2) * 455
        sheet.paste(image, (x, y + 22)); draw.text((x, y), name, fill=TEXT)
    sheet.save(OUT / "fig3_fig6_contact_sheet.png", dpi=(150, 150))
    print("[DONE] Wrote PDF, SVG, 300-dpi PNG, and contact sheet for all four figures.")

if __name__ == "__main__": main()
