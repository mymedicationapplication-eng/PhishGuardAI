import json
import warnings
from functools import lru_cache
import joblib
from flask import current_app

@lru_cache(maxsize=1)
def load_model():
    path = current_app.config["MODEL_PATH"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return joblib.load(path)

@lru_cache(maxsize=1)
def get_metrics():
    try:
        with open(current_app.config["METRICS_PATH"], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def predict_message(text: str):
    model = load_model()
    probabilities = model.predict_proba([text])[0]
    classes = list(model.classes_)
    probability_map = dict(zip(classes, probabilities))
    phishing_probability = float(probability_map.get(1, 0.0))
    legitimate_probability = float(probability_map.get(0, 0.0))
    prediction = int(model.predict([text])[0])
    label = "Phishing" if prediction == 1 else "Legitimate"
    confidence = phishing_probability if prediction == 1 else legitimate_probability
    return {
        "prediction": prediction,
        "label": label,
        "confidence": round(confidence * 100, 2),
        "phishing_probability": round(phishing_probability * 100, 2),
        "legitimate_probability": round(legitimate_probability * 100, 2),
    }
