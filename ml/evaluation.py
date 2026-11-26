import numpy as np

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix
)


def evaluate_predictions(y_true, y_pred, labels):
    """Return class-aware metrics and a labeled confusion matrix."""
    if len(y_true) == 0:
        raise ValueError("Evaluation requires at least one labeled record.")

    y_true = list(map(str, y_true))
    y_pred = list(map(str, y_pred))
    labels = sorted(set(map(str, labels)) | set(y_true) | set(y_pred))
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    true_positives = np.diag(matrix)
    support = matrix.sum(axis=1)
    predicted_count = matrix.sum(axis=0)
    precision = np.divide(
        true_positives,
        predicted_count,
        out=np.zeros(len(labels), dtype=float),
        where=predicted_count != 0
    )
    recall = np.divide(
        true_positives,
        support,
        out=np.zeros(len(labels), dtype=float),
        where=support != 0
    )
    f1 = np.divide(
        2 * precision * recall,
        precision + recall,
        out=np.zeros(len(labels), dtype=float),
        where=(precision + recall) != 0
    )
    supported = support > 0

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(recall[supported].mean()),
        "macro_f1": float(f1[supported].mean()),
        "weighted_f1": float(np.average(f1, weights=support)),
        "per_class": {
            label: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index])
            }
            for index, label in enumerate(labels)
        },
        "confusion_matrix": {
            "labels": labels,
            "values": matrix.tolist()
        }
    }
