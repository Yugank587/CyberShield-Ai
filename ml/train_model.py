import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from ml.evaluation import evaluate_predictions

# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_DIR / "datasets"
MODEL_DIR = PROJECT_DIR / "models"

MODEL_PATH = MODEL_DIR / "cybershield_model.joblib"
TEMP_MODEL_PATH = MODEL_DIR / "cybershield_model.joblib.tmp"
EVALUATION_PATH = MODEL_DIR / "model_evaluation.json"
HOLDOUT_FILE = os.getenv(
    "CYBERSHIELD_HOLDOUT_FILE",
    "Tuesday-WorkingHours.pcap_ISCX.csv"
)

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

def collect_training_data(holdout_file=HOLDOUT_FILE):

    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            "No CSV files found in the datasets folder."
        )

    training_samples = {}
    holdout_samples = {}
    total_rows = 0

    print("\nReading CIC-IDS2017 dataset...")
    print("Dataset folder:", DATASET_DIR)

    if not any(path.name == holdout_file for path in csv_files):
        raise FileNotFoundError(
            f"Holdout CSV '{holdout_file}' was not found. "
            "Set CYBERSHIELD_HOLDOUT_FILE to an available dataset file."
        )

    for file_path in csv_files:
        samples = (
            holdout_samples
            if file_path.name == holdout_file
            else training_samples
        )

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

    if not training_samples or not holdout_samples:
        raise ValueError(
            "Training and holdout files must both contain usable records."
        )

    def finalize_samples(samples, description):
        data = pd.concat(list(samples.values()), ignore_index=True)
        data = data.drop_duplicates().sample(
            frac=1,
            random_state=RANDOM_STATE
        ).reset_index(drop=True)

        if description == "training":
            class_counts = data["Target"].value_counts()
            rare_classes = class_counts[class_counts < 2].index.tolist()

            if rare_classes:
                print("\nClasses excluded due to insufficient training samples:")
                for label in rare_classes:
                    print("-", label)
                data = data[~data["Target"].isin(rare_classes)].copy()

        return data

    training_data = finalize_samples(training_samples, "training")
    holdout_data = finalize_samples(holdout_samples, "holdout")

    if training_data.empty or holdout_data.empty:
        raise ValueError(
            "The selected files did not produce usable training and holdout records."
        )

    print("\n" + "=" * 65)
    print("LEAKAGE-RESISTANT DATASET SUMMARY")
    print("=" * 65)

    print("Total rows scanned:", f"{total_rows:,}")
    print("Training records:", f"{len(training_data):,}")
    print("Held-out records:", f"{len(holdout_data):,}")
    print("Held-out file:", holdout_file)

    print("\nTraining records per attack category:")

    print(
        training_data["Target"]
        .value_counts()
        .to_string()
    )

    print("\nHeld-out records per attack category:")
    print(holdout_data["Target"].value_counts().to_string())

    return training_data, holdout_data


# --------------------------------------------------
# MODEL TRAINING
# --------------------------------------------------

def build_model():
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
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


def train_model(holdout_file=HOLDOUT_FILE):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    training_data, holdout_data = collect_training_data(holdout_file)
    X_train = training_data.drop(columns=["Target"])
    y_train = training_data["Target"].astype(str)

    X_train = X_train.dropna(axis=1, how="all")
    feature_columns = X_train.columns.tolist()

    if y_train.nunique() < 2 or (y_train.value_counts() < 2).any():
        raise ValueError(
            "Training requires at least two classes with two records each."
        )

    X_holdout = holdout_data.reindex(columns=feature_columns).copy()
    y_holdout = holdout_data["Target"].astype(str)

    training_hashes = pd.util.hash_pandas_object(
        X_train,
        index=False
    ).to_numpy()
    holdout_hashes = pd.util.hash_pandas_object(
        X_holdout,
        index=False
    ).to_numpy()
    duplicate_holdout_rows = np.isin(
        holdout_hashes,
        training_hashes
    )
    removed_duplicates = int(duplicate_holdout_rows.sum())
    X_holdout = X_holdout.loc[~duplicate_holdout_rows]
    y_holdout = y_holdout.loc[~duplicate_holdout_rows]

    if X_holdout.empty:
        raise ValueError(
            "All holdout records duplicate training features; "
            "choose a different CYBERSHIELD_HOLDOUT_FILE."
        )

    print("\nNumber of model features:", len(feature_columns))
    print("Training classes:", y_train.nunique())
    print("Training records:", f"{len(X_train):,}")
    print("Held-out records:", f"{len(X_holdout):,}")
    print("Duplicate holdout records removed:", f"{removed_duplicates:,}")

    print("\nFitting grouped-holdout evaluation model...")
    evaluation_model = build_model()
    evaluation_model.fit(X_train, y_train)

    predictions = evaluation_model.predict(X_holdout)
    evaluation = evaluate_predictions(
        y_holdout.tolist(),
        predictions.tolist(),
        set(evaluation_model.classes_) | set(y_holdout.unique())
    )
    unseen_holdout_labels = sorted(
        set(y_holdout.unique()) - set(evaluation_model.classes_)
    )

    production_data = pd.concat(
        [training_data, holdout_data],
        ignore_index=True
    ).drop_duplicates().reset_index(drop=True)
    X_production = production_data.reindex(columns=feature_columns).copy()
    y_production = production_data["Target"].astype(str)

    print("\nFitting final model on all available labeled source files...")
    model = build_model()
    model.fit(X_production, y_production)

    detection_limitation_note = (
        "These labels were absent from the evaluation model's training "
        "split and could not be predicted in this holdout: "
        + ", ".join(unseen_holdout_labels)
        + ". The final model is retrained on all source files, including "
        "these labels, but this evaluation does not validate its "
        "generalization to them."
        if unseen_holdout_labels
        else (
            "All holdout labels were represented in the evaluation "
            "training split. The final model is retrained on all source "
            "files; this same-corpus result is not external validation."
        )
    )

    training_files = sorted(
        path.name
        for path in DATASET_DIR.glob("*.csv")
        if path.name != holdout_file
    )
    model_report = {
        "model_type": "multiclass",
        "python_version": sys.version.split()[0],
        "sklearn_version": sklearn.__version__,
        "evaluation_method": (
            "The evaluation model was fit on every source CSV except the "
            "complete holdout file. Exact feature duplicates of evaluation "
            "training rows were removed before scoring. After evaluation, "
            "the final saved model was retrained on all available source "
            "files, including the holdout; the metrics describe the "
            "evaluation model, not an external validation set."
        ),
        "holdout_file": holdout_file,
        "training_files": training_files,
        "training_records": int(len(X_train)),
        "holdout_records": int(len(X_holdout)),
        "final_model_training_files": sorted(
            path.name for path in DATASET_DIR.glob("*.csv")
        ),
        "final_model_training_records": int(len(X_production)),
        "model_classes": [str(label) for label in model.classes_],
        "duplicate_holdout_records_removed": removed_duplicates,
        "random_state": RANDOM_STATE,
        "pipeline": {
            "imputer": "median",
            "classifier": {
                "name": "RandomForestClassifier",
                "n_estimators": 150,
                "max_depth": 25,
                "min_samples_split": 4,
                "min_samples_leaf": 2,
                "class_weight": "balanced"
            }
        },
        "sampling_limits": {
            "benign_training_records": BENIGN_LIMIT,
            "attack_training_records_per_class": ATTACK_LIMIT_PER_CATEGORY
        },
        "sampling_note": (
            "The same per-class caps are applied independently to training "
            "and holdout data. Weighted metrics reflect this sampled class "
            "distribution, not natural network prevalence."
        ),
        "unseen_holdout_labels": unseen_holdout_labels,
        "detection_limitation_note": detection_limitation_note,
        "probability_note": (
            "Random Forest predict_proba scores are uncalibrated and must "
            "not be interpreted as calibrated incident probabilities."
        ),
        "macro_f1_note": (
            "Macro F1 averages only labels with support in the holdout; "
            "per-class entries still include zero-support labels."
        ),
        "metrics": evaluation
    }

    print("\nHeld-out evaluation:")
    print(json.dumps(model_report, indent=2))

    model_data = {
        "model": model,
        "feature_columns": feature_columns,
        "target_mapping": {
            str(label): str(label)
            for label in model.classes_
        },
        "model_type": "multiclass",
        "model_classes": [str(label) for label in model.classes_],
        "evaluation": model_report
    }

    evaluation_temp_path = EVALUATION_PATH.with_suffix(".json.tmp")
    with evaluation_temp_path.open("w", encoding="utf-8") as report_file:
        json.dump(model_report, report_file, indent=2)
        report_file.write("\n")

    joblib.dump(model_data, TEMP_MODEL_PATH)
    TEMP_MODEL_PATH.replace(MODEL_PATH)
    evaluation_temp_path.replace(EVALUATION_PATH)

    print("\nModel saved:", MODEL_PATH)
    print("Evaluation report saved:", EVALUATION_PATH)
    print("Supported attack categories:")
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