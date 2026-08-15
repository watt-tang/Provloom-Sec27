"""Figure 5: conventional two-block metric heatmap."""
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from figure_style import *

configure()
rows = ["Full", "Static only", "Event only", "No alignment", "No policy"]
detection_cols = ["Precision", "Recall", "F1"]
false_positive_cols = ["FPR", "BL-FPR", "TA-FPR"]
detection = np.array([[.882, .731, .799], [.847, 1.000, .917], [.789, .628, .699],
                      [.858, .653, .742], [.583, .942, .720]])
false_positive = np.array([[.103, .000, .325], [.190, .173, .242], [.177, .034, .508],
                           [.114, .022, .325], [.709, .793, .833]])
assert np.allclose(detection[0], [.882, .731, .799])
assert np.allclose(false_positive[0], [.103, .000, .325])

blue_map = LinearSegmentedColormap.from_list("soft_blue", ["#FFFFFF", "#DCECF5", PROVLOOM_FULL])
warm_map = LinearSegmentedColormap.from_list("soft_warm", ["#FFFFFF", "#FBE8E1", POLICY_WARNING])
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 2.55),
                               gridspec_kw={"wspace": .34, "width_ratios": [1, 1]})

def heatmap(ax, matrix, cols, cmap, title, show_rows):
    ax.imshow(matrix, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(3), cols); ax.set_yticks(range(5), rows if show_rows else [""] * 5)
    ax.tick_params(length=0, pad=4)
    ax.set_title(title, loc="left", pad=8, fontsize=8.2)
    for i in range(5):
        for j in range(3):
            ax.text(j, i, f"{matrix[i, j]:.3f}", ha="center", va="center", fontsize=7.2,
                    weight="bold" if i == 0 else "normal")
    ax.set_xticks(np.arange(-.5, 3, 1), minor=True)
    ax.set_yticks(np.arange(-.5, 5, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=1.2)
    ax.tick_params(which="minor", bottom=False, left=False)
    for spine in ax.spines.values(): spine.set_visible(False)

heatmap(ax1, detection, detection_cols, blue_map, "Detection", True)
heatmap(ax2, false_positive, false_positive_cols, warm_map, "False-positive rates", False)
fig.subplots_adjust(left=.22, right=.98, top=.91, bottom=.16)
save(fig, "fig5_ablation")
