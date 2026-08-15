"""Shared publication style for the ProvLoom USENIX Security figures."""
from pathlib import Path
import matplotlib as mpl
import matplotlib.pyplot as plt

PROVLOOM_FULL = "#0082D3"
PROVLOOM_STATIC = "#76B2CE"
NEUTRAL = "#E9EAEE"
NEUTRAL_LIGHT = "#E7F1F0"
VIOLATION = "#FB7677"
POLICY_WARNING = "#D6671B"
PARTIAL = "#FFC2AD"
TRUSTED = "#A8C9DC"
LIGHT_FILL = "#FEF2F6"
PANEL_FILL = "#E8EEFA"
TEXT = "#20252B"
MUTED = "#68727D"

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "latex/USENIX_2027_Cycle1_Provloom/figures/generated"

def configure():
    mpl.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 7.5,
        "axes.titlesize": 8.2, "axes.titleweight": "normal",
        "axes.labelsize": 7.5, "xtick.labelsize": 7.2, "ytick.labelsize": 7.2,
        "legend.fontsize": 7.2, "pdf.fonttype": 42, "ps.fonttype": 42,
        "figure.dpi": 150, "savefig.dpi": 300, "savefig.bbox": "tight",
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.spines.left": False, "axes.spines.bottom": True,
        "axes.edgecolor": "#AAB2BB", "axes.linewidth": 0.6,
        "xtick.color": MUTED, "ytick.color": TEXT, "text.color": TEXT,
        "axes.labelcolor": MUTED,
    })

def save(fig, stem):
    OUT.mkdir(parents=True, exist_ok=True)
    for suffix, kwargs in (("pdf", {}), ("svg", {}), ("png", {"dpi": 300})):
        fig.savefig(OUT / f"{stem}.{suffix}", **kwargs)
    plt.close(fig)

def panel_label(ax, label):
    ax.text(-0.16, 1.035, label, transform=ax.transAxes, weight="bold",
            va="bottom", ha="left", fontsize=8.5)

def light_grid(ax):
    ax.grid(axis="x", color="#D9DEE4", linewidth=0.45, alpha=0.75)
    ax.set_axisbelow(True)
