import matplotlib.pyplot as plt
import numpy as np
import os

# Create graphs folder
os.makedirs("graphs", exist_ok=True)

# Dataset names
datasets = ["Dataset 1\n(UCI)", "Dataset 2\n(Kaggle)"]

# Final model results
accuracy = [96.11, 95.45]
precision = [95.76, 95.40]
recall = [97.32, 95.50]
f1_score = [96.54, 95.45]


# ==========================================
# GRAPH 1: PERFORMANCE COMPARISON
# ==========================================

x = np.arange(len(datasets))
width = 0.2

plt.figure(figsize=(10, 6))

plt.bar(x - 1.5 * width, accuracy, width, label="Accuracy")
plt.bar(x - 0.5 * width, precision, width, label="Precision")
plt.bar(x + 0.5 * width, recall, width, label="Recall")
plt.bar(x + 1.5 * width, f1_score, width, label="F1-Score")

plt.xlabel("Dataset")
plt.ylabel("Performance (%)")
plt.title("Logistic Regression Performance Comparison")

plt.xticks(x, datasets)
plt.ylim(90, 100)

plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.4)

plt.tight_layout()

plt.savefig(
    "graphs/performance_comparison.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ==========================================
# GRAPH 2: ACCURACY ONLY
# ==========================================

plt.figure(figsize=(8, 5))

bars = plt.bar(datasets, accuracy)

plt.xlabel("Dataset")
plt.ylabel("Accuracy (%)")
plt.title("Accuracy Comparison")

plt.ylim(90, 100)

# Display values on bars
for bar, value in zip(bars, accuracy):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.1,
        f"{value:.2f}%",
        ha="center"
    )

plt.grid(axis="y", linestyle="--", alpha=0.4)

plt.tight_layout()

plt.savefig(
    "graphs/accuracy_comparison.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ==========================================
# GRAPH 3: ALL METRICS AS LINE GRAPH
# ==========================================

plt.figure(figsize=(10, 6))

plt.plot(datasets, accuracy, marker="o", label="Accuracy")
plt.plot(datasets, precision, marker="o", label="Precision")
plt.plot(datasets, recall, marker="o", label="Recall")
plt.plot(datasets, f1_score, marker="o", label="F1-Score")

plt.xlabel("Dataset")
plt.ylabel("Performance (%)")
plt.title("Performance Metrics Across Datasets")

plt.ylim(90, 100)

plt.legend()
plt.grid(True, linestyle="--", alpha=0.4)

plt.tight_layout()

plt.savefig(
    "graphs/performance_line_graph.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


print("\nGraphs created successfully!")
print("Check the 'graphs' folder.")