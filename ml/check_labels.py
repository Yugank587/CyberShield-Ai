
from pathlib import Path
from collections import Counter
import pandas as pd

DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets"
CHUNK_SIZE = 100_000


def check_labels():
    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSV files found.")
        return

    overall_counts = Counter()

    print("=" * 70)
    print("CYBERSHIELD AI - FULL DATASET LABEL ANALYSIS")
    print("=" * 70)

    for file_path in csv_files:
        print(f"\nProcessing: {file_path.name}")

        file_counts = Counter()
        total_rows = 0

        try:
            for chunk in pd.read_csv(
                file_path,
                chunksize=CHUNK_SIZE,
                low_memory=False
            ):
                chunk.columns = chunk.columns.str.strip()

                label_column = next(
                    (col for col in chunk.columns
                     if col.lower() == "label"),
                    None
                )

                if label_column is None:
                    raise ValueError("Label column not found.")

                labels = (
                    chunk[label_column]
                    .astype("string")
                    .str.strip()
                )

                counts = labels.value_counts(dropna=False)

                for label, count in counts.items():
                    label_name = (
                        "MISSING" if pd.isna(label) else str(label)
                    )
                    file_counts[label_name] += int(count)

                total_rows += len(chunk)

            overall_counts.update(file_counts)

            print("Total rows:", f"{total_rows:,}")
            print("Labels:")

            for label, count in file_counts.most_common():
                print(f"  {label}: {count:,}")

        except Exception as error:
            print("ERROR:", error)
            return

    print("\n" + "=" * 70)
    print("OVERALL LABEL DISTRIBUTION")
    print("=" * 70)

    for label, count in overall_counts.most_common():
        print(f"{label}: {count:,}")

    print("\nTotal records:", f"{sum(overall_counts.values()):,}")
    print("\nLABEL ANALYSIS COMPLETED")


if __name__ == "__main__":
    check_labels()
