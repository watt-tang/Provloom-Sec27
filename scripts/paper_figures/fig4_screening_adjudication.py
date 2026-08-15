"""Figure 4: binary detection and benign-lookalike false positives."""
import matplotlib.pyplot as plt
from figure_style import *

configure()
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.35),
                               gridspec_kw={"wspace": 0.78, "width_ratios": [1.0, 0.92]})
methods = ["ProvLoom Static", "Cisco", "ProvLoom Full", "SkillScan", "AI-Infra-Guard"]
scores = [0.917, 0.8342, 0.7995, 0.5143, 0.4008]
bars = ax1.barh(range(5), scores, color=[PROVLOOM_STATIC, NEUTRAL, PROVLOOM_FULL, NEUTRAL, NEUTRAL], height=0.46)
ax1.set_yticks(range(5), methods); ax1.invert_yaxis(); ax1.set_xlim(0, 1.0)
ax1.set_xlabel("Binary F1", labelpad=3); ax1.set_title("Binary detection", loc="left", pad=7); light_grid(ax1)
for b, v in zip(bars, scores):
    ax1.text(v + 0.022, b.get_y() + b.get_height()/2, f"{v:.3f}", va="center", fontsize=7)
panel_label(ax1, "(a)")

bl_labels = ["Static only", "ProvLoom Full"]
bl_values = [17.3, 0.0]
bl_colors = [PROVLOOM_STATIC, PROVLOOM_FULL]
bars = ax2.barh([0, 1], bl_values, color=bl_colors, height=0.46)
ax2.set_yticks([0, 1], bl_labels); ax2.invert_yaxis(); ax2.set_xlim(0, 20)
ax2.set_xlabel("BL-FPR (%)", labelpad=3)
ax2.set_title("(b) Benign-lookalike false positives", loc="left", pad=7)
light_grid(ax2)
for b, v, color in zip(bars, bl_values, bl_colors):
    if v == 0:
        ax2.plot(0, b.get_y() + b.get_height()/2, marker="s", markersize=4.2,
                 color=color, clip_on=False, zorder=3)
    ax2.text(max(v + 0.55, 0.55), b.get_y() + b.get_height()/2,
             f"{v:.1f}%", va="center", ha="left", fontsize=7)
save(fig, "fig4_screening_adjudication")
