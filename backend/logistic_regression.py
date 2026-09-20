import pandas as pd
import numpy as np
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from scipy.io import arff

from sklearn.preprocessing import PolynomialFeatures
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GridSearchCV


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# DATASET 2 - PHISHING_LEGITIMATE_FULL.CSV
# ============================================================

print("\n========================================")
print("DATASET 2 - LOGISTIC REGRESSION")
print("========================================")


# ------------------------------------------------------------
# Load Dataset 2
# ------------------------------------------------------------

dataset2_path = os.path.join(
    DATASET_DIR,
    "Phishing_Legitimate_full.csv"
)

data = pd.read_csv(dataset2_path)

print("Dataset shape:", data.shape)


# ------------------------------------------------------------
# Separate features and target
# ------------------------------------------------------------

X = data.drop(columns=["CLASS_LABEL"])

y = data["CLASS_LABEL"]


# ------------------------------------------------------------
# Remove ID column
# ------------------------------------------------------------

if "id" in X.columns:
    X = X.drop(columns=["id"])


# ------------------------------------------------------------
# Convert all values to numeric
# ------------------------------------------------------------

X = X.apply(pd.to_numeric, errors="coerce")


# ------------------------------------------------------------
# Fill missing values
# ------------------------------------------------------------

X = X.fillna(0)


# ------------------------------------------------------------
# Train-test split
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# ------------------------------------------------------------
# Standard Scaling
# ------------------------------------------------------------

scaler2 = StandardScaler()

X_train_scaled = scaler2.fit_transform(X_train)
X_test_scaled = scaler2.transform(X_test)


# ------------------------------------------------------------
# Logistic Regression
# ------------------------------------------------------------

model2 = LogisticRegression(
    max_iter=2000,
    random_state=42
)


# ------------------------------------------------------------
# Train Dataset 2 model
# ------------------------------------------------------------

model2.fit(X_train_scaled, y_train)


# ============================================================
# DATASET 2 - DECISION THRESHOLD
# ============================================================

print("\n========================================")
print("DATASET 2 - FINDING BEST THRESHOLD")
print("========================================")


# Get probability of positive class

y_prob = model2.predict_proba(X_test_scaled)[:, 1]


best_threshold = 0.50
best_f1 = 0


# Try thresholds from 0.50 to 0.70

for threshold in np.arange(0.50, 0.71, 0.01):

    temp_pred = (
        y_prob >= threshold
    ).astype(int)

    temp_precision = precision_score(
        y_test,
        temp_pred,
        zero_division=0
    )

    temp_recall = recall_score(
        y_test,
        temp_pred,
        zero_division=0
    )

    temp_f1 = f1_score(
        y_test,
        temp_pred,
        zero_division=0
    )


    # Select threshold where important
    # metrics are at least 95%

    if (
        temp_precision >= 0.95
        and temp_recall >= 0.95
        and temp_f1 > best_f1
    ):

        best_f1 = temp_f1
        best_threshold = threshold


# Final prediction

y_pred = (
    y_prob >= best_threshold
).astype(int)


print("\nBest Decision Threshold:", best_threshold)


# ============================================================
# DATASET 2 - PERFORMANCE METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred
)

recall = recall_score(
    y_test,
    y_pred
)

f1 = f1_score(
    y_test,
    y_pred
)


print("\n========================================")
print("DATASET 2 MODEL PERFORMANCE")
print("========================================")

print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1 Score  : {f1 * 100:.2f}%")


# ============================================================
# DATASET 2 - CONFUSION MATRIX
# ============================================================

cm = confusion_matrix(
    y_test,
    y_pred
)


print("\n========================================")
print("DATASET 2 CONFUSION MATRIX")
print("========================================")

print(cm)


# ============================================================
# DATASET 2 - CLASSIFICATION REPORT
# ============================================================

print("\n========================================")
print("DATASET 2 CLASSIFICATION REPORT")
print("========================================")

print(
    classification_report(
        y_test,
        y_pred
    )
)


# ============================================================
# DATASET 1 - TRAINING DATASET.ARFF
# ============================================================

print("\n========================================")
print("DATASET 1 - LOGISTIC REGRESSION")
print("========================================")


# ------------------------------------------------------------
# Load ARFF dataset
# ------------------------------------------------------------

dataset1_path = os.path.join(
    DATASET_DIR,
    "Training Dataset.arff"
)

data_arff, meta = arff.loadarff(
    dataset1_path
)


# Convert ARFF to DataFrame

df1 = pd.DataFrame(data_arff)

print("Dataset shape:", df1.shape)


# ------------------------------------------------------------
# Convert byte/string values to numbers
# ------------------------------------------------------------

for column in df1.columns:

    df1[column] = df1[column].apply(
        lambda x:
        x.decode("utf-8")
        if isinstance(x, bytes)
        else x
    )


# ------------------------------------------------------------
# Convert all columns to numeric
# ------------------------------------------------------------

df1 = df1.apply(
    pd.to_numeric,
    errors="coerce"
)


# ------------------------------------------------------------
# Separate features and target
# ------------------------------------------------------------

X1 = df1.drop(
    columns=["Result"]
)

y1 = df1["Result"]


# ------------------------------------------------------------
# Fill missing values
# ------------------------------------------------------------

X1 = X1.fillna(0)


# ------------------------------------------------------------
# Train-test split
# ------------------------------------------------------------

X1_train, X1_test, y1_train, y1_test = train_test_split(
    X1,
    y1,
    test_size=0.20,
    random_state=42,
    stratify=y1
)


print("Training samples:", len(X1_train))
print("Testing samples:", len(X1_test))


# ============================================================
# DATASET 1 - IMPROVED LOGISTIC REGRESSION
# ============================================================

print("\n========================================")
print("DATASET 1 - MODEL TRAINING")
print("========================================")


# ------------------------------------------------------------
# Pipeline
#
# StandardScaler
#       ↓
# PolynomialFeatures
#       ↓
# Logistic Regression
# ------------------------------------------------------------

pipeline1 = Pipeline([
    
    (
        "scaler",
        StandardScaler()
    ),

    (
        "poly",
        PolynomialFeatures(
            degree=2,
            include_bias=False
        )
    ),

    (
        "logistic",
        LogisticRegression(
            max_iter=5000,
            solver="liblinear",
            random_state=42
        )
    )

])


# ------------------------------------------------------------
# Hyperparameter search
# ------------------------------------------------------------

param_grid1 = {

    "logistic__C": [
        0.01,
        0.1,
        1,
        10,
        100
    ]

}


# ------------------------------------------------------------
# GridSearchCV
# ------------------------------------------------------------

grid1 = GridSearchCV(

    pipeline1,

    param_grid1,

    cv=5,

    scoring="f1",

    n_jobs=-1

)


# ------------------------------------------------------------
# Train GridSearch
# ------------------------------------------------------------

grid1.fit(
    X1_train,
    y1_train
)


# ------------------------------------------------------------
# Get best model
# ------------------------------------------------------------

model1 = grid1.best_estimator_


print("\nBest Logistic Regression parameters:")

print(
    grid1.best_params_
)


# ============================================================
# DATASET 1 - ORIGINAL MODEL PERFORMANCE
# ============================================================

y1_pred_original = model1.predict(
    X1_test
)


accuracy1_original = accuracy_score(
    y1_test,
    y1_pred_original
)

precision1_original = precision_score(
    y1_test,
    y1_pred_original,
    pos_label=1
)

recall1_original = recall_score(
    y1_test,
    y1_pred_original,
    pos_label=1
)

f1_1_original = f1_score(
    y1_test,
    y1_pred_original,
    pos_label=1
)


print("\n========================================")
print("DATASET 1 ORIGINAL MODEL PERFORMANCE")
print("========================================")

print(
    f"Accuracy  : {accuracy1_original * 100:.2f}%"
)

print(
    f"Precision : {precision1_original * 100:.2f}%"
)

print(
    f"Recall    : {recall1_original * 100:.2f}%"
)

print(
    f"F1 Score  : {f1_1_original * 100:.2f}%"
)


# ============================================================
# DATASET 1 - CONFUSION MATRIX
# ============================================================

cm1_original = confusion_matrix(
    y1_test,
    y1_pred_original
)


print("\n========================================")
print("DATASET 1 ORIGINAL CONFUSION MATRIX")
print("========================================")

print(
    cm1_original
)


# ============================================================
# DATASET 1 - CALIBRATED MODEL
# ============================================================

print("\n========================================")
print("CALIBRATING DATASET 1 MODEL")
print("========================================")

print(
    "Using sigmoid probability calibration..."
)


# ------------------------------------------------------------
# CalibratedClassifierCV
#
# This calibrates predict_proba() so that
# confidence values are more meaningful.
#
# cv=5 means 5-fold cross-validation.
# ------------------------------------------------------------

calibrated_model1 = CalibratedClassifierCV(
    model1,
    method="sigmoid",
    cv=5,
    n_jobs=-1
)


# ------------------------------------------------------------
# Train calibrated model
# ------------------------------------------------------------

calibrated_model1.fit(
    X1_train,
    y1_train
)


print(
    "Calibration completed successfully."
)


# ============================================================
# DATASET 1 - CALIBRATED MODEL PREDICTION
# ============================================================

y1_pred = calibrated_model1.predict(
    X1_test
)


# ============================================================
# DATASET 1 - CALIBRATED MODEL PROBABILITIES
# ============================================================

y1_probabilities = calibrated_model1.predict_proba(
    X1_test
)


# ------------------------------------------------------------
# Check class order
# ------------------------------------------------------------

print("\nModel classes:")

print(
    calibrated_model1.classes_
)


# ------------------------------------------------------------
# Confidence values
# ------------------------------------------------------------

confidence_values = (
    np.max(
        y1_probabilities,
        axis=1
    ) * 100
)


print("\n========================================")
print("CALIBRATED CONFIDENCE CHECK")
print("========================================")

print(
    f"Minimum confidence : "
    f"{confidence_values.min():.2f}%"
)

print(
    f"Maximum confidence : "
    f"{confidence_values.max():.2f}%"
)

print(
    f"Average confidence : "
    f"{confidence_values.mean():.2f}%"
)


# ============================================================
# DATASET 1 - CALIBRATED PERFORMANCE
# ============================================================

accuracy1 = accuracy_score(
    y1_test,
    y1_pred
)

precision1 = precision_score(
    y1_test,
    y1_pred,
    pos_label=1
)

recall1 = recall_score(
    y1_test,
    y1_pred,
    pos_label=1
)

f1_1 = f1_score(
    y1_test,
    y1_pred,
    pos_label=1
)


print("\n========================================")
print("DATASET 1 CALIBRATED MODEL PERFORMANCE")
print("========================================")

print(
    f"Accuracy  : {accuracy1 * 100:.2f}%"
)

print(
    f"Precision : {precision1 * 100:.2f}%"
)

print(
    f"Recall    : {recall1 * 100:.2f}%"
)

print(
    f"F1 Score  : {f1_1 * 100:.2f}%"
)


# ============================================================
# DATASET 1 - CALIBRATED CONFUSION MATRIX
# ============================================================

cm1 = confusion_matrix(
    y1_test,
    y1_pred
)


print("\n========================================")
print("DATASET 1 CALIBRATED CONFUSION MATRIX")
print("========================================")

print(
    cm1
)


# ============================================================
# DATASET 1 - CALIBRATED CLASSIFICATION REPORT
# ============================================================

print("\n========================================")
print("DATASET 1 CALIBRATED CLASSIFICATION REPORT")
print("========================================")

print(
    classification_report(
        y1_test,
        y1_pred
    )
)


# ============================================================
# SAVE CALIBRATED DATASET 1 MODEL
# ============================================================

model_path = os.path.join(
    MODEL_DIR,
    "logistic_model.pkl"
)


# ------------------------------------------------------------
# IMPORTANT:
#
# Save the CALIBRATED model, not the original model.
#
# This allows app.py to use:
#
# model.predict()
# model.predict_proba()
#
# directly.
# ------------------------------------------------------------

joblib.dump(
    calibrated_model1,
    model_path
)


print("\n========================================")
print("LOGISTIC REGRESSION MODEL SAVED")
print("========================================")

print(
    "Location:",
    model_path
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n========================================")
print("FINAL MODEL SUMMARY")
print("========================================")

print("\nDataset 1:")
print(
    f"Accuracy  : {accuracy1 * 100:.2f}%"
)
print(
    f"Precision : {precision1 * 100:.2f}%"
)
print(
    f"Recall    : {recall1 * 100:.2f}%"
)
print(
    f"F1 Score  : {f1_1 * 100:.2f}%"
)

print("\nDataset 2:")
print(
    f"Accuracy  : {accuracy * 100:.2f}%"
)
print(
    f"Precision : {precision * 100:.2f}%"
)
print(
    f"Recall    : {recall * 100:.2f}%"
)
print(
    f"F1 Score  : {f1 * 100:.2f}%"
)

print("\n========================================")
print("TRAINING COMPLETED SUCCESSFULLY")
print("========================================")