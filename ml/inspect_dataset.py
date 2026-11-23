
from pathlib import Path
import pandas as pd

DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets"

def inspect_datasets():
    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSV files found in the datasets folder.")
        return

    print("=" * 75)
    print("CYBERSHIELD AI - CIC-IDS2017 DATASET INSPECTION")
    print("=" * 75)

    for file_path in csv_files:
        print(f"\nFILE: {file_path.name}")
        print("-" * 75)

        try:
            # Read only five rows to avoid loading large files into memory.
            df = pd.read_csv(file_path, nrows=5, low_memory=False)

            # Remove accidental spaces from column names.
            df.columns = df.columns.str.strip()

            print("Number of columns:", len(df.columns))
            print("\nColumn names:")
            for column in df.columns:
                print(" -", column)

            # Find the target label column.
            label_column = next(
                (col for col in df.columns if col.lower() == "label"),
                None
            )

            if label_column:
                print("\nSample labels:")
                print(df[label_column].value_counts().to_string())
            else:
                print("\nWARNING: Label column not found.")

        except Exception as error:
            print("Error inspecting file:", error)

    print("\n" + "=" * 75)
    print("DATASET INSPECTION COMPLETED")
    print("=" * 75)


if __name__ == "__main__":
    inspect_datasets()
