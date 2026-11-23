from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_DIR / "datasets"
MODEL_DIR = PROJECT_DIR / "models"

MODEL_PATH = MODEL_DIR / "cybershield_model.joblib"
TEMP_MODEL_PATH = MODEL_DIR / "cybershield_model.joblib.tmp"

CHUNK_SIZE = 100_000

BENIGN_LIMIT = 150_000
ATTACK_LIMIT_PER_CATEGORY = 10_000

RANDOM_STATE = 42


# --------------------------------------------------
# LABEL NORMALIZATION
# --------------------------------------------------

def normalize_label(value):

    label = str(value).strip()

    # Replace corrupted separator characters.
    label = label.replace("\ufffd", "-")
    label = label.replace("\uFFFD", "-")

    # Normalize dash characters.
    label = label.replace("–", "-")
    label = label.replace("—", "-")

    # Normalize spacing.
    label = " ".join(label.split())

    # Standardize known CIC-IDS2017 labels.
    known_labels = {
        "Web Attack - Brute Force":
            "Web Attack - Brute Force",

        "Web Attack - XSS":
            "Web Attack - XSS",

        "Web Attack - Sql Injection":
            "Web Attack - SQL Injection",

        "Web Attack - SQL Injection":
            "Web Attack - SQL Injection",

        "BENIGN": "BENIGN"
    }

    return known_labels.get(label, label)


# --------------------------------------------------
# DATA COLLECTION AND SAMPLING
# --------------------------------------------------

def collect_training_data():

    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            "No CSV files found in the datasets folder."
        )

    samples = {}
    total_rows = 0

    print("\nReading CIC-IDS2017 dataset...")
    print("Dataset folder:", DATASET_DIR)

    for file_path in csv_files:

        print("\nProcessing:", file_path.name)

        for chunk in pd.read_csv(
            file_path,
            chunksize=CHUNK_SIZE,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace"
        ):

            chunk.columns = (
                chunk.columns.astype(str).str.strip()
            )

            label_column = next(
                (
                    column for column in chunk.columns
                    if column.lower() == "label"
                ),
                None
            )

            if label_column is None:
                raise ValueError(
                    f"Label column missing in {file_path.name}"
                )

            chunk[label_column] = (
                chunk[label_column]
                .astype("string")
                .str.strip()
                .map(normalize_label)
            )

            chunk = chunk.dropna(
                subset=[label_column]
            )

            total_rows += len(chunk)

            # Remove duplicated CIC-IDS2017 feature.
            if "Fwd Header Length.1" in chunk.columns:
                chunk = chunk.drop(
                    columns=["Fwd Header Length.1"]
                )

            feature_columns = [
                column for column in chunk.columns
                if column != label_column
            ]

            # Convert model features into numeric values.
            for column in feature_columns:

                chunk[column] = pd.to_numeric(
                    chunk[column],
                    errors="coerce"
                )

            chunk[feature_columns] = (
                chunk[feature_columns].replace(
                    [np.inf, -np.inf],
                    np.nan
                )
            )

            # Remove rows with no usable feature values.
            chunk = chunk.dropna(
                subset=feature_columns,
                how="all"
            )

            # Sample each original attack category separately.
            for original_label, group in chunk.groupby(
                label_column,
                sort=False
            ):

                label = normalize_label(original_label)

                if label.upper() == "BENIGN":
                    limit = BENIGN_LIMIT
                    label = "BENIGN"
                else:
                    limit = ATTACK_LIMIT_PER_CATEGORY

                group = group.drop(
                    columns=[label_column]
                ).copy()

                group["Target"] = label

                if label not in samples:

                    samples[label] = group

                else:

                    samples[label] = pd.concat(
                        [samples[label], group],
                        ignore_index=True
                    )

                # Keep the configured maximum for each category.
                if len(samples[label]) > limit:

                    samples[label] = samples[label].sample(
                        n=limit,
                        random_state=RANDOM_STATE
                    ).reset_index(drop=True)

        print("Completed:", file_path.name)

    if not samples:
        raise ValueError(
            "No usable training records were found."
        )

    # Combine all sampled categories.
    data = pd.concat(
        list(samples.values()),
        ignore_index=True
    )

    # Remove duplicate feature and target records.
    data = data.drop_duplicates()

    # Shuffle the final dataset.
    data = data.sample(
        frac=1,
        random_state=RANDOM_STATE
    ).reset_index(drop=True)

    # Remove classes with fewer than two samples.
    class_counts = data["Target"].value_counts()

    rare_classes = class_counts[
        class_counts < 2
    ].index.tolist()

    if rare_classes:

        print("\nClasses excluded due to insufficient samples:")

        for label in rare_classes:
            print("-", label)

        data = data[
            ~data["Target"].isin(rare_classes)
        ].copy()

    if data.empty:
        raise ValueError(
            "No classes have enough records for model training."
        )

    print("\n" + "=" * 65)
    print("MULTICLASS DATASET SUMMARY")
    print("=" * 65)

    print("Total rows scanned:", f"{total_rows:,}")
    print("Sampled records:", f"{len(data):,}")

    print("\nRecords per attack category:")

    print(
        data["Target"]
        .value_counts()
        .to_string()
    )

    return data


# --------------------------------------------------
# MODEL TRAINING
# --------------------------------------------------

def train_model():

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    data = collect_training_data()

    X = data.drop(
        columns=["Target"]
    )

    y = data["Target"].astype(str)

    # Remove features containing only missing values.
    X = X.dropna(
        axis=1,
        how="all"
    )

    feature_columns = X.columns.tolist()

    class_counts = y.value_counts()

    if len(class_counts) < 2:
        raise ValueError(
            "Multiclass training requires at least two categories."
        )

    if (class_counts < 2).any():
        raise ValueError(
            "Every training category must contain at least two records."
        )

    print("\nNumber of model features:", len(feature_columns))
    print("Number of classes:", y.nunique())

    # Split the dataset while preserving category distribution.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print("\nTraining multiclass Random Forest classifier...")

    model = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="median")
        ),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=150,
                max_depth=25,
                min_samples_split=4,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1
            )
        )
    ])

    model.fit(
        X_train,
        y_train
    )

    # --------------------------------------------------
    # MODEL EVALUATION
    # --------------------------------------------------

    print("\nEvaluating multiclass model...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(
        "\nOverall accuracy:",
        round(accuracy * 100, 2),
        "%"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            labels=model.classes_,
            zero_division=0
        )
    )

    print("\nConfusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=model.classes_
        )
    )

    # --------------------------------------------------
    # SAVE MULTICLASS MODEL
    # --------------------------------------------------

    model_data = {
        "model": model,
        "feature_columns": feature_columns,

        "target_mapping": {
            str(label): str(label)
            for label in model.classes_
        },

        "model_type": "multiclass",
        "model_classes": [
            str(label) for label in model.classes_
        ]
    }

    print("\nSaving trained model...")

    joblib.dump(
        model_data,
        TEMP_MODEL_PATH
    )

    # Replace the previous model only after successful saving.
    TEMP_MODEL_PATH.replace(MODEL_PATH)

    print("\n" + "=" * 65)
    print("CYBERSHIELD AI MULTICLASS TRAINING COMPLETED")
    print("=" * 65)

    print("Model saved successfully:")
    print(MODEL_PATH)

    print("\nSupported attack categories:")

    for label in model.classes_:
        print("-", label)


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":

    try:
        train_model()

    except Exception as error:

        print("\nMODEL TRAINING FAILED")
        print("Reason:", error)

        raise