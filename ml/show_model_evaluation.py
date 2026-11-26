import json
from pathlib import Path


REPORT_PATH = (
    Path(__file__).resolve().parent.parent
    / "models"
    / "model_evaluation.json"
)


def main():
    if not REPORT_PATH.is_file():
        raise SystemExit(
            "No held-out evaluation report is available. "
            "Run `python -m ml.train_model` with the CIC-IDS2017 files first."
        )

    with REPORT_PATH.open(encoding="utf-8") as report_file:
        report = json.load(report_file)

    metrics = report["metrics"]
    print("CIC-IDS2017 held-out model evaluation")
    print("Holdout file:", report["holdout_file"])
    print("Evaluation training records:", report["training_records"])
    print("Holdout records:", report["holdout_records"])
    print("Final model training records:", report["final_model_training_records"])
    print("Final model classes:", report["model_classes"])
    print("Unseen holdout labels:", report["unseen_holdout_labels"])
    print("Sampling note:", report["sampling_note"])
    print("Detection limitation:", report["detection_limitation_note"])
    print()
    print("Accuracy:", f"{metrics['accuracy']:.4f}")
    print("Balanced accuracy:", f"{metrics['balanced_accuracy']:.4f}")
    print("Macro F1:", f"{metrics['macro_f1']:.4f}")
    print("Weighted F1:", f"{metrics['weighted_f1']:.4f}")
    print()
    print("Per-class metrics:")
    for label, values in metrics["per_class"].items():
        print(
            f"{label}: precision={values['precision']:.4f}, "
            f"recall={values['recall']:.4f}, "
            f"F1={values['f1']:.4f}, "
            f"support={values['support']}"
        )


if __name__ == "__main__":
    main()
