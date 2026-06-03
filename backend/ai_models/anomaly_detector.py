"""
Anomaly Detection engine using Isolation Forest for zero-day / unknown attack detection.
Complements the supervised classifier with unsupervised scoring.
"""
import numpy as np
import threading
import time

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

_model = None
_lock = threading.Lock()
_sample_buffer = []
BUFFER_SIZE = 500
_trained = False


def _build_model():
    return IsolationForest(
        n_estimators=100,
        contamination=0.05,   # assume 5% anomalous traffic
        random_state=42,
        n_jobs=1,
        warm_start=False,
    )


def _maybe_train():
    global _model, _trained
    if len(_sample_buffer) < BUFFER_SIZE:
        return
    with _lock:
        if len(_sample_buffer) < BUFFER_SIZE:
            return
        data = np.array(_sample_buffer[-BUFFER_SIZE:])
        if _model is None:
            _model = _build_model()
        _model.fit(data)
        _trained = True
        print(f"[AnomalyDetector] Retrained on {len(data)} samples")


def score(features: np.ndarray) -> dict:
    """
    Returns:
        anomaly_score: float (more negative = more anomalous)
        is_anomaly: bool
        confidence: float 0-100
    """
    if not SKLEARN_AVAILABLE:
        return {"anomaly_score": 0.0, "is_anomaly": False, "confidence": 0.0}

    vec = features.flatten().tolist()
    _sample_buffer.append(vec[:4])   # use first 4 features for speed

    if len(_sample_buffer) % 50 == 0:
        threading.Thread(target=_maybe_train, daemon=True).start()

    if not _trained or _model is None:
        return {"anomaly_score": 0.0, "is_anomaly": False, "confidence": 0.0}

    try:
        sample = np.array([vec[:4]])
        raw_score = _model.score_samples(sample)[0]   # negative, lower = more anomalous
        prediction = _model.predict(sample)[0]         # -1 = anomaly, 1 = normal

        # Normalise to 0-100 confidence
        # Typical score_samples range: -0.7 to 0.2
        clamped = max(-0.7, min(0.2, raw_score))
        confidence = ((0.2 - clamped) / 0.9) * 100

        return {
            "anomaly_score": round(raw_score, 4),
            "is_anomaly": prediction == -1,
            "confidence": round(confidence, 1)
        }
    except Exception as e:
        return {"anomaly_score": 0.0, "is_anomaly": False, "confidence": 0.0}
