import pandas as pd
from scipy.io import arff
import os

file_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dataset",
    "Training Dataset.arff"
)

data, metadata = arff.loadarff(file_path)

df = pd.DataFrame(data)

# Convert byte values
for column in df.columns:
    if df[column].dtype == object:
        df[column] = df[column].apply(
            lambda x: x.decode("utf-8") if isinstance(x, bytes) else x
        )

print("\n==============================")
print("DATASET FEATURE INFORMATION")
print("==============================")

print("Total columns:", len(df.columns))

print("\nFeature names:")

for i, column in enumerate(df.columns[:-1]):
    print(i + 1, "->", column)

print("\nTarget column:")
print(df.columns[-1])