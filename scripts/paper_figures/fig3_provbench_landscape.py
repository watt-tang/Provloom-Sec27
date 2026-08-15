"""Figure 3: ProvBench composition, shown as two stacked standard bar panels."""
import numpy as np
import matplotlib.pyplot as plt
from figure_style import *

configure()
N = 776
semantics = ["Confirmed violations", "Benign lookalikes", "Trusted allowed", "Review / coverage"]
semantic_counts = [398, 179, 120, 79]
dimensions = ["Network / external", "LLM mediated", "Multi-file"]
dimension_counts = [579, 316, 199]
assert sum(semantic_counts) == N

fig = plt.figure(figsize=(7.0, 3.85))
gs = fig.add_gridspec(2, 1, height_ratios=[1.12, .92], hspace=.58)
ax1 = fig.add_subplot(gs[0])
ax2 = fig.add_subplot(gs[1])

bars = ax1.barh(np.arange(4), semantic_counts,
                color=[VIOLATION, TRUSTED, NEUTRAL_LIGHT, PARTIAL], height=.48)
ax1.set_yticks(np.arange(4), semantics); ax1.invert_yaxis(); ax1.set_xlim(0, 480)
ax1.set_title("(a) Security semantics", loc="left", pad=7, fontsize=8.2)
ax1.set_xlabel("Cases", labelpad=3); light_grid(ax1)
for b, v in zip(bars, semantic_counts):
    ax1.text(v + 8, b.get_y() + b.get_height()/2, f"{v} ({v/N:.1%})",
             va="center", ha="left", fontsize=7)

bars = ax2.barh(np.arange(3), dimension_counts,
                color=[PROVLOOM_FULL, PROVLOOM_STATIC, NEUTRAL], height=.48)
ax2.set_yticks(np.arange(3), dimensions); ax2.invert_yaxis(); ax2.set_xlim(0, 680)
ax2.set_title("(b) Execution characteristics", loc="left", pad=7, fontsize=8.2)
ax2.set_xlabel("Cases", labelpad=3); light_grid(ax2)
for b, v in zip(bars, dimension_counts):
    ax2.text(v + 10, b.get_y() + b.get_height()/2, str(v),
             va="center", ha="left", fontsize=7)
save(fig, "fig3_provbench_landscape")
