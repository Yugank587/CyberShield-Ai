import io
import unittest
from unittest.mock import patch

import numpy as np

from ml.inference import analyze_uploaded_csv


class StubModel:
    def predict(self, features):
        return np.array(["ATTACK", "BENIGN"])[:len(features)]

    def predict_proba(self, features):
        return np.array([[0.2, 0.8], [0.9, 0.1]])[:len(features)]


class CsvInferenceTests(unittest.TestCase):
    def test_analysis_returns_bounded_results_and_source_details(self):
        csv_data = (
            "Flow Duration,Source IP,Destination IP,Label\n"
            "10,192.0.2.1,198.51.100.1,ATTACK\n"
            "20,192.0.2.2,198.51.100.2,BENIGN\n"
        )
        with patch(
            "ml.inference.load_detection_model",
            return_value=(
                StubModel(),
                ["Flow Duration"],
                {"ATTACK": "DDoS", "BENIGN": "BENIGN"}
            )
        ):
            result = analyze_uploaded_csv(
                io.BytesIO(csv_data.encode("utf-8"))
            )

        self.assertEqual(result["total_records"], 2)
        self.assertEqual(result["threats_detected"], 1)
        self.assertEqual(result["benign_records"], 1)
        self.assertEqual(result["attack_breakdown"][0]["attack_type"], "DDoS")
        self.assertEqual(
            result["threat_records"][0]["details"]["source_ip"],
            "192.0.2.1"
        )

    def test_missing_model_features_are_rejected(self):
        with patch(
            "ml.inference.load_detection_model",
            return_value=(StubModel(), ["Flow Duration", "Protocol"], {})
        ):
            with self.assertRaisesRegex(ValueError, "missing required"):
                analyze_uploaded_csv(
                    io.BytesIO(b"Flow Duration,Label\n10,ATTACK\n")
                )

    def test_rows_with_no_numeric_features_are_rejected(self):
        with patch(
            "ml.inference.load_detection_model",
            return_value=(StubModel(), ["Flow Duration"], {})
        ):
            with self.assertRaisesRegex(ValueError, "no usable"):
                analyze_uploaded_csv(
                    io.BytesIO(
                        b"Flow Duration\nnot-a-number\n"
                    )
                )


if __name__ == "__main__":
    unittest.main()
