import math
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import joblib

app = Flask(__name__)

# 🔒 MAXIMUM CONTENT PACKET LIMITATION (Memory Guard)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024  

# ✅ NEW LINE (Allows your GitHub website to connect instantly):

CORS(app, resources={r"/*": {"origins": "*"}})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishingmodel.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "tfidfvectorizer.pkl")

print("⏳ Loading pre-trained Machine Learning model files into RAM...")
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
print("🧠 AI Model loaded successfully. Server ready!")

# 🗄️ INDUSTRY MATRIX DATABASES
WHITELIST_DOMAINS = ["google.com", "youtube.com", "github.com", "microsoft.com", "amazon.in", "wikipedia.org", "yahoo.com", "paypal.com", "netflix.com"]
BLACKLIST_DOMAINS = ["free-netflix-gift.xyz", "secure-paypal-login-update.net", "verify-meta-account.info"]
HIGH_RISK_TLDS = {".xyz", ".top", ".biz", ".info", ".cc", ".icu", ".click", ".tk"}
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "banking", "account", "suspend", "wallet", "signin", "free"]
TARGET_BRANDS = ["google", "paypal", "amazon", "netflix", "microsoft", "github", "facebook"]

def calculate_entropy(domain: str) -> float:
    """Calculates Shannon Entropy to detect randomly generated domains."""
    if not domain:
        return 0.0
    frequencies = [float(domain.count(c)) / len(domain) for c in set(domain)]
    entropy = -sum(p * math.log(p, 2) for p in frequencies)
    return entropy

@app.route('/scan', methods=['POST'])
def scan_url():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL parameter found in request"}), 400
        
    target_url = data.get('url', '')
    
    if not isinstance(target_url, str):
        return jsonify({"error": "Data format error: Input must be a string text"}), 400
        
    target_url = target_url.strip()

    if len(target_url) < 4 or "." not in target_url:
        return jsonify({
            "score": 100,
            "status": "BLOCKED BY SYSTEM FIREWALL",
            "details": ["Invalid web address structure or potential code injection detected."]
        }), 400
        
    lower_url = target_url.lower()
    
    # 🩹 CORE FIXED STRING PARSER: Extracts just the domain segment as a clean text string, never a list
    clean_url = lower_url.replace("https://", "").replace("http://", "").replace("www.", "")
    core_domain = clean_url.split('/')[0] # Grab just the first text piece before any path slash

    # -----------------------------------------------------------------
    # LAYER 1: DATA MATRIX VERIFICATION (Instant Pass / Block)
    # -----------------------------------------------------------------
    if core_domain in WHITELIST_DOMAINS:
        return jsonify({
            "score": 0,
            "status": "SAFE",
            "details": ["Verified Trusted Domain (Global Whitelist Pass)"]
        })

    if core_domain in BLACKLIST_DOMAINS:
        return jsonify({
            "score": 100,
            "status": "MALICIOUS PHISHING SITE",
            "details": ["Instant Block: Domain matches signature in global threat database"]
        })

    # -----------------------------------------------------------------
    # LAYER 2: ADVANCED STRUCTURAL & MATHEMATICAL SCAN
    # -----------------------------------------------------------------
    rule_penalty = 0
    reasons_flagged = []

    if lower_url.startswith("http://"):
        rule_penalty += 25
        reasons_flagged.append("Insecure protocol (HTTP used instead of HTTPS)")

    if "@" in lower_url:
        rule_penalty += 40
        reasons_flagged.append("URL obfuscation detected (Tricky '@' character usage)")

    if len(lower_url) > 60:
        rule_penalty += 15
        reasons_flagged.append("URL text is suspiciously long (Hides true domain name)")

    domain_entropy = calculate_entropy(core_domain)
    if domain_entropy > 4.0:
        rule_penalty += 20
        reasons_flagged.append(f"High Shannon Entropy ({domain_entropy:.2f}): Domain text appears randomly generated")

    for tld in HIGH_RISK_TLDS:
        if core_domain.endswith(tld):
            rule_penalty += 25
            reasons_flagged.append(f"Suspicious Domain Extension ({tld}): Heavily used in automated phishing campaigns")
            break

    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in lower_url]
    if len(found_keywords) >= 2:
        rule_penalty += 20
        reasons_flagged.append(f"High Suspicious Keyword Density: Multiple social engineering keywords found ({', '.join(found_keywords)})")

    for brand in TARGET_BRANDS:
        if brand in core_domain and core_domain not in WHITELIST_DOMAINS:
            rule_penalty += 35
            reasons_flagged.append(f"Brand Impersonation Alert: Domain structurally mimics a protected trademark ({brand})")
            break

    # -----------------------------------------------------------------
    # LAYER 3: MACHINE LEARNING PATTERN PROBABILITY
    # -----------------------------------------------------------------
    url_numeric = vectorizer.transform([target_url])
    probabilities = model.predict_proba(url_numeric)
    
    # 🩹 ML ARRAY FIXED: Pulls out the 1D probabilistic element from the matrix reliably
    ai_risk_score = int(probabilities[0][1] * 100) 
    
    # -----------------------------------------------------------------
    # AGGREGATION ENGINE (Combining Threat Vectors)
    # -----------------------------------------------------------------
    final_risk_score = ai_risk_score + rule_penalty
    if final_risk_score > 100:
        final_risk_score = 100

    if final_risk_score >= 70:
        status = "MALICIOUS PHISHING SITE"
    elif final_risk_score >= 35:
        status = "SUSPICIOUS (PROCEED WITH CAUTION)"
    else:
        status = "SAFE"
        
    return jsonify({
        "score": final_risk_score,
        "status": status,
        "details": reasons_flagged if reasons_flagged else ["Passed structural checks. Verified by AI pattern match alone."]
    })

if __name__ == '__main__':
    # Cloud environments pass down a dynamic PORT variable. We check for it, or default to 5000.
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # Turn off debug mode for cloud safety

