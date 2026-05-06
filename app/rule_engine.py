from .text_utils import extract_urls

SUSPICIOUS_RULES = {
    "urgency": {
        "weight": 9,
        "terms": ["urgent", "immediately", "asap", "act now", "limited time", "final warning", "suspended", "verify now"],
    },
    "credentials": {
        "weight": 12,
        "terms": ["password", "passcode", "otp", "pin", "verify your account", "login", "credential", "reset password"],
    },
    "financial": {
        "weight": 10,
        "terms": ["payment", "invoice", "refund", "bank", "transfer", "credit card", "wallet", "billing"],
    },
    "threat": {
        "weight": 10,
        "terms": ["account blocked", "account suspended", "security alert", "unauthorized", "compromised", "breach"],
    },
    "social_engineering": {
        "weight": 8,
        "terms": ["click here", "claim prize", "gift card", "winner", "free", "confirm identity", "download attachment"],
    },
    "sensitive_request": {
        "weight": 11,
        "terms": ["ssn", "social security", "passport", "cvv", "secret", "private key", "seed phrase"],
    },
}

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "cutt.ly"]

def analyze_rules(message: str, phishing_probability: float):
    text = (message or "").lower()
    urls = extract_urls(message)
    hits = []
    score = 0

    for category, data in SUSPICIOUS_RULES.items():
        matched_terms = [term for term in data["terms"] if term in text]
        if matched_terms:
            score += data["weight"] + min(len(matched_terms) * 2, 8)
            hits.extend(matched_terms)

    for url in urls:
        if url.startswith("http://"):
            score += 10
            hits.append("non-secure link")
        if any(shortener in url.lower() for shortener in SHORTENERS):
            score += 8
            hits.append("shortened url")
        if "@" in url or len(url.split(".")) > 4:
            score += 6
            hits.append("unusual url structure")

    score += int((phishing_probability / 100) * 40)

    unique_hits = list(dict.fromkeys(hits))
    risk_score = max(0, min(100, score))

    if risk_score >= 75:
        risk_level = "High"
        recommendation = "Do not click any links or share any credentials. Verify the sender through an official channel."
    elif risk_score >= 45:
        risk_level = "Medium"
        recommendation = "Treat this message cautiously. Inspect the sender, links, and requests before taking action."
    else:
        risk_level = "Low"
        recommendation = "No strong phishing signals were found, but continue to review the message carefully before responding."

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "suspicious_keywords": unique_hits,
        "detected_urls": urls,
        "recommendation": recommendation,
    }
