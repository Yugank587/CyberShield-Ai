import json
import os
import unittest
from pathlib import Path

import joblib
import pandas as pd

os.environ["APP_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-only-cybershield-secret"
os.environ["DATABASE_URL"] = "sqlite://"

import app as app_module
from ml.evaluation import evaluate_predictions
from ml import train_model


class ModelTests(unittest.TestCase):
    def test_saved_model_accepts_the_declared_feature_schema(self):
        model, feature_columns, target_mapping = (
            app_module.load_detection_model()
        )
        self.assertEqual(len(feature_columns), 77)
        self.assertEqual(len(set(feature_columns)), 77)
        self.assertTrue(target_mapping)

        row = pd.DataFrame(
            [[0.0] * len(feature_columns)],
            columns=feature_columns
        )
        probabilities = model.predict_proba(row)
        self.assertEqual(probabilities.shape[0], 1)
        self.assertTrue(
            all(0.0 <= value <= 1.0 for value in probabilities[0])
        )
        self.assertAlmostEqual(float(probabilities[0].sum()), 1.0)

    def test_evaluation_report_matches_saved_model_metadata(self):
        project_dir = Path(__file__).resolve().parent.parent
        model_data = joblib.load(
            project_dir / "models" / "cybershield_model.joblib"
        )
        report = json.loads(
            (project_dir / "models" / "model_evaluation.json")
            .read_text(encoding="utf-8")
        )

        self.assertEqual(model_data["evaluation"], report)
        self.assertIn("detection_limitation_note", report)
        self.assertIn("macro_f1_note", report)
        self.assertEqual(model_data["model_classes"], report["model_classes"])
        self.assertTrue(
            set(report["unseen_holdout_labels"]).issubset(
                set(model_data["model_classes"])
            )
        )

    def test_evaluation_reports_class_imbalance_and_unseen_labels(self):
        report = evaluate_predictions(
            ["BENIGN", "ATTACK", "ATTACK"],
            ["BENIGN", "BENIGN", "ATTACK"],
            ["BENIGN", "ATTACK", "UNSEEN"]
        )

        self.assertAlmostEqual(report["accuracy"], 2 / 3)
        self.assertEqual(report["per_class"]["UNSEEN"]["support"], 0)
        self.assertEqual(
            report["confusion_matrix"]["labels"],
            ["ATTACK", "BENIGN", "UNSEEN"]
        )
        self.assertEqual(
            len(report["confusion_matrix"]["values"]),
            3
        )
        self.assertAlmostEqual(
            report["macro_f1"],
            (
                report["per_class"]["ATTACK"]["f1"]
                + report["per_class"]["BENIGN"]["f1"]
            ) / 2
        )

    def test_evaluation_counts_predictions_for_unobserved_classes(self):
        report = evaluate_predictions(
            ["BENIGN", "BENIGN"],
            ["ATTACK", "BENIGN"],
            ["BENIGN"]
        )

        self.assertIn("ATTACK", report["per_class"])
        self.assertEqual(report["per_class"]["ATTACK"]["support"], 0)
        self.assertEqual(report["per_class"]["ATTACK"]["precision"], 0.0)
        self.assertEqual(report["per_class"]["BENIGN"]["recall"], 0.5)
        self.assertAlmostEqual(report["macro_f1"], 2 / 3)

    def test_training_data_keeps_holdout_file_separate(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        with TemporaryDirectory() as directory:
            data_dir = Path(directory)
            pd.DataFrame({
                "Flow Duration": [1, 2, 3, 4],
                "Label": ["BENIGN", "BENIGN", "DDoS", "DDoS"]
            }).to_csv(data_dir / "training.csv", index=False)
            pd.DataFrame({
                "Flow Duration": [5, 6],
                "Label": ["BENIGN", "UNSEEN"]
            }).to_csv(data_dir / "holdout.csv", index=False)

            with patch.object(train_model, "DATASET_DIR", data_dir):
                training, holdout = train_model.collect_training_data(
                    "holdout.csv"
                )

        self.assertEqual(set(training["Target"]), {"BENIGN", "DDoS"})
        self.assertEqual(set(holdout["Target"]), {"BENIGN", "UNSEEN"})

    def test_final_model_includes_labels_from_the_holdout_file(self):
        from tempfile import TemporaryDirectory
        from unittest.mock import patch

        with TemporaryDirectory() as directory:
            root = Path(directory)
            data_dir = root / "datasets"
            model_dir = root / "models"
            data_dir.mkdir()
            pd.DataFrame({
                "Flow Duration": [1, 2, 3, 4],
                "Label": ["BENIGN", "BENIGN", "DDoS", "DDoS"]
            }).to_csv(data_dir / "training.csv", index=False)
            pd.DataFrame({
                "Flow Duration": [5, 6, 7, 8],
                "Label": ["BENIGN", "BENIGN", "UNSEEN", "UNSEEN"]
            }).to_csv(data_dir / "holdout.csv", index=False)

            model_path = model_dir / "model.joblib"
            evaluation_path = model_dir / "evaluation.json"
            with patch.object(train_model, "DATASET_DIR", data_dir), \
                    patch.object(train_model, "MODEL_DIR", model_dir), \
                    patch.object(train_model, "MODEL_PATH", model_path), \
                    patch.object(
                        train_model,
                        "TEMP_MODEL_PATH",
                        model_dir / "model.joblib.tmp"
                    ), \
                    patch.object(
                        train_model,
                        "EVALUATION_PATH",
                        evaluation_path
                    ):
                train_model.train_model("holdout.csv")

            saved_model = joblib.load(model_path)
            report = json.loads(
                evaluation_path.read_text(encoding="utf-8")
            )

        self.assertIn("UNSEEN", saved_model["model_classes"])
        self.assertIn("UNSEEN", report["unseen_holdout_labels"])
        self.assertEqual(report["final_model_training_records"], 8)
        self.assertEqual(saved_model["evaluation"], report)


if __name__ == "__main__":
    unittest.main()
