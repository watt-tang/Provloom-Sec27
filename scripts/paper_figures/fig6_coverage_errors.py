"""Figure 6: coverage and error attribution as standard case-count bars."""
import numpy as np
import matplotlib.pyplot as plt
from figure_style import *

configure()
N = 776
coverage_labels = ["Complete", "Path incomplete", "Exec. failure", "Timeout", "Missing env.", "Reached, no flow", "Not triggered", "Max steps"]
coverage_counts = [290, 309, 83, 40, 25, 21, 5, 3]
assert sum(coverage_counts) == N

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.65),
                               gridspec_kw={"wspace": .92, "width_ratios": [1.0, 1.06]})
bars = ax1.barh(np.arange(8), coverage_counts,
                color=[PROVLOOM_STATIC, PARTIAL, NEUTRAL, NEUTRAL, NEUTRAL, PARTIAL, PARTIAL, NEUTRAL], height=.42)
ax1.set_yticks(np.arange(8), coverage_labels); ax1.invert_yaxis(); ax1.set_xlim(0, 365)
ax1.set_title("(a) Coverage states", loc="left", pad=7, fontsize=8.2)
ax1.set_xlabel("Cases", labelpad=3); light_grid(ax1)
for b, v in zip(bars, coverage_counts):
    ax1.text(v + 6, b.get_y() + b.get_height()/2, f"{v} ({v/N:.1%})",
             va="center", ha="left", fontsize=6.8)

error_labels = ["FN: Coverage / realization", "FN: Provenance", "FN: Execution", "FN: Policy", "FP: Trusted-allowed policy"]
error_counts = [103, 3, 1, 0, 39]
error_colors = [PARTIAL, TRUSTED, NEUTRAL, NEUTRAL, PROVLOOM_FULL]
y = np.array([4, 3, 2, 1, -1])
bars = ax2.barh(y, error_counts, color=error_colors, height=.42)
ax2.set_yticks(y, error_labels); ax2.set_xlim(0, 110); ax2.set_ylim(-1.8, 4.65)
ax2.set_title("(b) Error attribution", loc="left", pad=7, fontsize=8.2)
ax2.set_xlabel("Cases", labelpad=3); light_grid(ax2)
for b, v in zip(bars, error_counts):
    ax2.text(v + 4 if v else 3, b.get_y() + b.get_height()/2, str(v),
             va="center", ha="left", fontsize=7)
save(fig, "fig6_coverage_errors")
