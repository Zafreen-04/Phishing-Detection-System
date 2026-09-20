import pandas as pd
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from xgboost import XGBClassifier

# Dataset location
file_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dataset",
    "Training Dataset.arff"
)

# Load dataset
from scipy.io import arff

data, metadata = arff.loadarff(file_path)

df = pd.DataFrame(data)

# Convert byte values to normal text
for column in df.columns:
    if df[column].dtype == object:
        df[column] = df[column].apply(
            lambda x: x.decode("utf-8") if isinstance(x, bytes) else x
        )

print("Dataset loaded successfully")
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])
print("Column names:")
print(df.columns.tolist())

# Convert all columns to numbers
df = df.apply(pd.to_numeric, errors="coerce")

# Remove missing values
df = df.dropna()

# Last column is the target
X = df.iloc[:, :-1]
y = df.iloc[:, -1]

# Convert target labels from -1, 1 to 0, 1
y = y.replace({-1: 0, 1: 1}).astype(int)

print("Features:", X.shape[1])
print("Samples:", X.shape[0])
print("Target classes:", y.unique())

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training the XGBoost model...")

# Create model
model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric="logloss"
)

# Train
model.fit(X_train, y_train)

# Prediction
y_pred = model.predict(X_test)

# ==============================
# MODEL EVALUATION
# ==============================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n==============================")
print("MODEL TRAINING COMPLETED")
print("==============================")

print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1-Score  : {f1 * 100:.2f}%")

# Confusion Matrix
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Detailed Classification Report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ==============================
# SAVE MODEL
# ==============================

model_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
    "phishing_model.pkl"
)

joblib.dump(model, model_path)

print("\nModel saved successfully!")
print("Location:", model_path)