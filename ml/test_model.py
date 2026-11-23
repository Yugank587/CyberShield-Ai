
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_DIR / "models" / "cybershield_model.joblib"
DATASET_DIR = PROJECT_DIR / "datasets"


def test_attack_detection():

    print("=" * 65)
    print("CYBERSHIELD AI - BENIGN AND ATTACK DETECTION TEST")
    print("=" * 65)

    saved_data = joblib.load(MODEL_PATH)

    model = saved_data["model"]
    feature_columns = saved_data["feature_columns"]

    # Choose one file containing both benign and DDoS records.
    file_path = (
        DATASET_DIR /
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    )

    print("\nLoading:", file_path.name)

    # Read the file in chunks until we find both categories.
    selected = []
    found_benign = False
    found_attack = False

    for chunk in pd.read_csv(
        file_path,
        chunksize=100_000,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace"
    ):

        chunk.columns = chunk.columns.str.strip()

        label_column = next(
            (c for c in chunk.columns if c.lower() == "label"),
            None
        )

        if label_column is None:
            raise ValueError("Label column not found.")

        labels = chunk[label_column].astype("string").str.strip()

        benign = chunk[labels.str.upper() == "BENIGN"].head(10)
        attack = chunk[labels.str.upper() == "DDOS"].head(10)

        if not benign.empty:
            selected.append(benign)
            found_benign = True

        if not attack.empty:
            selected.append(attack)
            found_attack = True

        if found_benign and found_attack:
            break

    if not selected:
        print("No test records found.")
        return

    data = pd.concat(selected, ignore_index=True)

    actual_labels = (
        data[label_column]
        .astype("string")
        .str.strip()
        .tolist()
    )

    data = data.drop(columns=[label_column])

    if "Fwd Header Length.1" in data.columns:
        data = data.drop(columns=["Fwd Header Length.1"])

    for column in data.columns:
        data[column] = pd.to_numeric(
            data[column], errors="coerce"
        )

    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.reindex(columns=feature_columns)

    predictions = model.predict(data)

    print("\nPREDICTION RESULTS")
    print("-" * 65)

    correct = 0

    for i, prediction in enumerate(predictions):

        actual = (
            "BENIGN"
            if actual_labels[i].upper() == "BENIGN"
            else "ATTACK"
        )

        predicted = (
            "ATTACK" if prediction == 1 else "BENIGN"
        )

        result = "CORRECT" if actual == predicted else "INCORRECT"

        if actual == predicted:
            correct += 1

        print(
            f"Record {i + 1:02d} | "
            f"Actual: {actual:6s} | "
            f"Predicted: {predicted:6s} | "
            f"{result}"
        )

    print("\nTotal records:", len(predictions))
    print("Correct predictions:", correct)
    print("Incorrect predictions:", len(predictions) - correct)

    print("\nTEST COMPLETED")


if __name__ == "__main__":
    test_attack_detection()
