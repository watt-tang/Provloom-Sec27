from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle


OUTPUT_DIR = Path(__file__).resolve().parents[1] / "Latex" / "figures"

HIGH_CRITICAL = [
    {"system": "ProvLoom", "mal": 7, "ambig": 7, "benign": 12, "total": 26},
    {"system": "SkillScan", "mal": 6, "ambig": 60, "benign": 266, "total": 332},
    {"system": "Cisco", "mal": 9, "ambig": 69, "benign": 320, "total": 398},
    {"system": "ClawVet", "mal": 9, "ambig": 50, "benign": 185, "total": 244},
    {"system": "SkillFortify", "mal": 15, "ambig": 66, "benign": 250, "total": 331},
]

MEDIUM_PLUS = [
    {"system": "ProvLoom", "mal": 15, "ambig": 30, "benign": 120, "total": 165},
    {"system": "SkillScan", "mal": 8, "ambig": 69, "benign": 293, "total": 370},
    {"system": "Cisco", "mal": 9, "ambig": 69, "benign": 322, "total": 400},
    {"system": "ClawVet", "mal": 17, "ambig": 56, "benign": 250, "total": 323},
    {"system": "SkillFortify", "mal": 15, "ambig": 66, "benign": 250, "total": 331},
]

MAX_TOTAL = 400


def configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 8.5,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "svg.fonttype": "none",
        }
    )


def draw_panel(ax: plt.Axes, rows: list[dict[str, int | str]], panel_id: str, title: str) -> None:
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Column anchors
    x_system = 0.06
    x_mal = 0.43
    x_ambig = 0.57
    x_benign = 0.72
    x_total = 0.865
    x_bar = 0.91
    bar_w = 0.07

    # Vertical layout
    title_y = 0.965
    header_y = 0.83
    rule_y = 0.775
    first_y = 0.68
    row_step = 0.125
    row_h = 0.085
    tint_y = 0.12
    tint_h = 0.63

    # Panel title line
    ax.text(
        0.03,
        title_y,
        panel_id,
        ha="left",
        va="top",
        fontsize=9,
        fontweight="bold",
        color="#202020",
    )
    ax.text(
        0.11,
        title_y,
        title,
        ha="left",
        va="top",
        fontsize=9,
        fontweight="bold",
        color="#202020",
    )

    # Subtle column hints
    ax.add_patch(Rectangle((x_mal - 0.045, tint_y), 0.09, tint_h, facecolor="#FEF7F7", edgecolor="none", zorder=0))
    ax.add_patch(Rectangle((x_ambig - 0.05, tint_y), 0.10, tint_h, facecolor="#FFFCF4", edgecolor="none", zorder=0))
    ax.add_patch(Rectangle((x_benign - 0.055, tint_y), 0.11, tint_h, facecolor="#FAFAFA", edgecolor="none", zorder=0))

    # Headers
    headers = [
        ("System", x_system, "left"),
        ("Mal.", x_mal, "center"),
        ("Ambig.", x_ambig, "center"),
        ("Benign", x_benign, "center"),
        ("Total", x_total, "center"),
    ]
    for label, x, ha in headers:
        ax.text(x, header_y, label, ha=ha, va="center", fontsize=7.8, fontweight="semibold", color="#3A3A3A")

    ax.plot([0.05, 0.98], [rule_y, rule_y], color="#D6D6D6", lw=0.8, solid_capstyle="butt")

    for i, row in enumerate(rows):
        y = first_y - i * row_step
        is_provloom = row["system"] == "ProvLoom"

        if is_provloom:
            ax.add_patch(Rectangle((0.05, y - row_h / 2), 0.93, row_h, facecolor="#FAFBFC", edgecolor="none", zorder=-1))

        ax.plot([0.05, 0.98], [y - row_h / 2, y - row_h / 2], color="#E7E7E7", lw=0.55, solid_capstyle="butt")

        name_weight = "medium" if is_provloom else "normal"
        num_weight = "medium" if is_provloom else "normal"
        total_color = "#546878" if is_provloom else "#4B4B4B"
        bar_color = "#708696" if is_provloom else "#D1D1D1"

        ax.text(x_system, y, str(row["system"]), ha="left", va="center", fontsize=8.2, fontweight=name_weight, color="#222222")
        ax.text(x_mal, y, f'{row["mal"]}', ha="center", va="center", fontsize=8.2, color="#962F32", fontweight=num_weight)
        ax.text(x_ambig, y, f'{row["ambig"]}', ha="center", va="center", fontsize=8.2, color="#8A6722", fontweight=num_weight)
        ax.text(x_benign, y, f'{row["benign"]}', ha="center", va="center", fontsize=8.2, color="#4A4A4A", fontweight=num_weight)
        ax.text(x_total, y, f'{row["total"]}', ha="right", va="center", fontsize=8.2, color=total_color, fontweight=num_weight)

        # Light total scale indicator
        ax.add_patch(Rectangle((x_bar, y - 0.012), bar_w, 0.024, facecolor="#F3F3F3", edgecolor="none"))
        fill_w = bar_w * (float(row["total"]) / MAX_TOTAL)
        ax.add_patch(Rectangle((x_bar, y - 0.012), fill_w, 0.024, facecolor=bar_color, edgecolor="none"))

    y_bottom = first_y - (len(rows) - 1) * row_step - row_h / 2
    ax.plot([0.05, 0.98], [y_bottom, y_bottom], color="#DFDFDF", lw=0.6, solid_capstyle="butt")


def make_double_column_figure() -> None:
    configure_matplotlib()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.45))
    fig.patch.set_facecolor("white")

    draw_panel(axes[0], HIGH_CRITICAL, "(A)", "High or critical")
    draw_panel(axes[1], MEDIUM_PLUS, "(B)", "Medium or higher")

    plt.subplots_adjust(left=0.02, right=0.995, top=0.98, bottom=0.06, wspace=0.10)

    pdf_path = OUTPUT_DIR / "fig_realworld_thresholds.pdf"
    png_path = OUTPUT_DIR / "fig_realworld_thresholds.png"
    svg_path = OUTPUT_DIR / "fig_realworld_thresholds.svg"

    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(svg_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=400, bbox_inches="tight")
    plt.close(fig)

    print(f"Wrote {pdf_path}")
    print(f"Wrote {png_path}")
    print(f"Wrote {svg_path}")


def make_single_column_figure() -> None:
    configure_matplotlib()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(2, 1, figsize=(3.45, 3.05))
    fig.patch.set_facecolor("white")

    draw_panel(axes[0], HIGH_CRITICAL, "(A)", "High or critical")
    draw_panel(axes[1], MEDIUM_PLUS, "(B)", "Medium or higher")

    plt.subplots_adjust(left=0.03, right=0.99, top=0.985, bottom=0.05, hspace=0.16)

    pdf_path = OUTPUT_DIR / "fig_realworld_thresholds_singlecol.pdf"
    png_path = OUTPUT_DIR / "fig_realworld_thresholds_singlecol.png"
    svg_path = OUTPUT_DIR / "fig_realworld_thresholds_singlecol.svg"

    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(svg_path, bbox_inches="tight")
    fig.savefig(png_path, dpi=400, bbox_inches="tight")
    plt.close(fig)

    print(f"Wrote {pdf_path}")
    print(f"Wrote {png_path}")
    print(f"Wrote {svg_path}")


if __name__ == "__main__":
    make_double_column_figure()
    make_single_column_figure()
