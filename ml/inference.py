from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_DIR / "models" / "cybershield_model.joblib"
ANALYSIS_CHUNK_SIZE = 50_000
MAX_THREAT_RECORDS = 1000


def load_detection_model():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            "The trained CyberShield AI model was not found. "
            "Please train the model first."
        )

    saved_data = joblib.load(MODEL_PATH)
    if (
        not isinstance(saved_data, dict)
        or "model" not in saved_data
        or "feature_columns" not in saved_data
    ):
        raise ValueError("The saved model file has an invalid format.")

    model = saved_data["model"]
    feature_columns = saved_data["feature_columns"]
    if (
        not isinstance(feature_columns, list)
        or not feature_columns
        or len(feature_columns) != len(set(feature_columns))
    ):
        raise ValueError(
            "The saved model has an invalid or duplicate feature schema."
        )

    if not hasattr(model, "predict_proba"):
        raise ValueError(
            "The saved model does not support prediction probabilities. "
            "Please train the multiclass model again."
        )

    return model, feature_columns, saved_data.get("target_mapping", {})


def safe_value(value):
    if pd.isna(value):
        return "N/A"

    if isinstance(value, np.integer):
        return int(value)

    if isinstance(value, np.floating):
        value = float(value)

    if isinstance(value, float):
        if not np.isfinite(value):
            return "N/A"
        if value.is_integer():
            return int(value)
        return round(value, 4)

    return str(value)


def find_column(columns, candidates):
    lookup = {
        str(column).strip().lower(): column
        for column in columns
    }

    for candidate in candidates:
        if candidate.lower() in lookup:
            return lookup[candidate.lower()]
    return None


def get_flow_details(row):
    field_candidates = {
        "source_ip": ["Source IP", "Src IP", "Source Address"],
        "destination_ip": ["Destination IP", "Dst IP", "Destination Address"],
        "source_port": ["Source Port", "Src Port"],
        "destination_port": ["Destination Port", "Dst Port"],
        "protocol": ["Protocol"],
        "timestamp": ["Timestamp", "Flow Timestamp"],
        "flow_duration": ["Flow Duration"],
        "total_fwd_packets": ["Total Fwd Packets"],
        "total_bwd_packets": ["Total Backward Packets"]
    }

    details = {}
    for field, candidates in field_candidates.items():
        column = find_column(row.index, candidates)
        details[field] = (
            safe_value(row[column])
            if column is not None
            else "N/A"
        )
    return details


def analyze_uploaded_csv(file_stream):
    model, feature_columns, target_mapping = load_detection_model()

    total_records = 0
    threats_detected = 0
    benign_records = 0
    skipped_records = 0
    attack_counts = {}
    attack_confidence_totals = {}
    attack_confidence_counts = {}
    attack_flow_samples = {}
    confidence_total = 0.0
    confidence_count = 0
    threat_records = []

    chunks = pd.read_csv(
        file_stream,
        chunksize=ANALYSIS_CHUNK_SIZE,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace"
    )

    for chunk in chunks:
        if chunk.empty:
            continue

        chunk.columns = chunk.columns.astype(str).str.strip()
        if chunk.columns.duplicated().any():
            raise ValueError(
                "The uploaded CSV contains duplicate column names."
            )

        original_rows = chunk.copy()
        label_column = next(
            (
                column for column in chunk.columns
                if column.lower() == "label"
            ),
            None
        )
        if label_column:
            chunk = chunk.drop(columns=[label_column])
        if "Fwd Header Length.1" in chunk.columns:
            chunk = chunk.drop(columns=["Fwd Header Length.1"])

        missing_features = [
            feature for feature in feature_columns
            if feature not in chunk.columns
        ]
        if missing_features:
            raise ValueError(
                "The uploaded CSV is missing required model features: "
                + ", ".join(missing_features[:8])
            )

        features = chunk.reindex(columns=feature_columns).copy()
        for column in feature_columns:
            features[column] = pd.to_numeric(
                features[column],
                errors="coerce"
            )
        features = features.replace([np.inf, -np.inf], np.nan)

        valid_rows = ~features.isna().all(axis=1)
        skipped_records += int((~valid_rows).sum())
        valid_features = features.loc[valid_rows]
        if valid_features.empty:
            continue

        valid_original_rows = original_rows.loc[valid_rows]
        predictions = model.predict(valid_features)
        probabilities = model.predict_proba(valid_features)
        score_values = probabilities.max(axis=1) * 100
        first_record_number = total_records + 1
        total_records += len(predictions)

        for index, prediction in enumerate(predictions):
            prediction = str(prediction)
            mapped_prediction = target_mapping.get(
                prediction,
                prediction
            )
            score = float(score_values[index])

            if str(mapped_prediction).upper() == "BENIGN":
                benign_records += 1
                continue

            threats_detected += 1
            attack_counts[mapped_prediction] = (
                attack_counts.get(mapped_prediction, 0) + 1
            )
            attack_confidence_totals[mapped_prediction] = (
                attack_confidence_totals.get(mapped_prediction, 0.0)
                + score
            )
            attack_confidence_counts[mapped_prediction] = (
                attack_confidence_counts.get(mapped_prediction, 0) + 1
            )
            confidence_total += score
            confidence_count += 1

            details = get_flow_details(
                valid_original_rows.iloc[index]
            )
            samples = attack_flow_samples.setdefault(
                mapped_prediction,
                []
            )
            if len(samples) < 3:
                samples.append({
                    "confidence": round(score, 2),
                    "details": details
                })

            if len(threat_records) < MAX_THREAT_RECORDS:
                threat_records.append({
                    "record_number": first_record_number + index,
                    "attack_type": mapped_prediction,
                    "confidence": round(score, 2),
                    "severity": (
                        "Critical" if score >= 95
                        else "High" if score >= 85
                        else "Medium"
                    ),
                    "details": details
                })

    if total_records == 0:
        raise ValueError(
            "The uploaded CSV contains no usable network-flow records."
        )

    attack_breakdown = []
    for attack_type, count in sorted(
        attack_counts.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        category_count = attack_confidence_counts[attack_type]
        attack_breakdown.append({
            "attack_type": attack_type,
            "count": count,
            "percentage": round(
                count / threats_detected * 100,
                2
            ) if threats_detected else 0,
            "average_confidence": round(
                attack_confidence_totals[attack_type] / category_count,
                2
            ),
            "flow_samples": attack_flow_samples.get(attack_type, [])
        })

    average_confidence = (
        confidence_total / confidence_count
        if confidence_count else 0
    )

    return {
        "total_records": total_records,
        "threats_detected": threats_detected,
        "benign_records": benign_records,
        "skipped_records": skipped_records,
        "attack_breakdown": attack_breakdown,
        "threat_records": threat_records,
        "average_confidence": round(average_confidence, 2),
        "records_displayed": len(threat_records),
        "records_limit": MAX_THREAT_RECORDS
    }
