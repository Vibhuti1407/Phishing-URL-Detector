import pandas as pd
import numpy as np
import re
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

def get_entropy(text):
    if not text: return 0
    probs = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in probs)

# 1. Feature Extraction Functions
def extract_features(url):
    features = {}
    url = str(url).lower()
    parsed_url = urlparse(url)
    
    # Structural features
    features['URLLength'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['has_at'] = 1 if '@' in url else 0
    features['is_https'] = 1 if url.startswith('https') else 0
    
    # Domain-based features
    domain = parsed_url.netloc
    features['domain_len'] = len(domain)
    features['num_subdomains'] = len(domain.split('.')) - 2 if domain else 0
    features['is_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
    features['digits_in_domain'] = sum(c.isdigit() for c in domain)
    features['entropy'] = get_entropy(domain) # Randomness check
    
    # Content features (Crucial for catching "paypal-login" etc.)
    suspicious_words = ['paypal', 'login', 'verify', 'bank', 'secure', 'update', 'account', 'ebay', 'amazon']
    features['num_suspicious_words'] = sum(1 for word in suspicious_words if word in url)

    # Suspicious TLD check 
    # .net is okay, but .biz, .top, .xyz, .cc are higher risk
    high_risk_tlds = ['.net', '.biz', '.top', '.xyz', '.cc', '.info', '.work']
    features['is_suspicious_tld'] = 1 if any(url.endswith(tld) for tld in high_risk_tlds) else 0

    # Keyword Scoring (Weighted)
    # We look for "amaz" and "payp" to catch "amaz0n" or "payp4l"
    targets = ['amaz', 'payp', 'log', 'verif', 'bank', 'secure', 'sign', 'account']
    features['bad_word_score'] = sum(2 for t in targets if t in url)

    # Enhanced Keyword Check (using Regex to catch partial matches)
    suspicious_patterns = ['amazon', 'payp', 'login', 'verify', 'secure', 'bank']
    features['num_suspicious_words'] = sum(1 for word in suspicious_patterns if word in url)

    return features

# 2. Training Logic
def train_model(csv_path):
    print(f"Loading dataset: {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # PhiUSIIL specific check: Ensure column 'URL' and 'label' exist
    # If your CSV uses 'status', change 'label' below to 'status'
    target_col = 'label' 
    url_col = 'URL'

    print("Extracting features (this may take a minute)...")
    # We want 1 to be PHISHING for easier SOC logic.
    if 'label' in df.columns:
        df['target'] = df['label'].apply(lambda x: 1 if x == 0 else 0)

    # We only use the raw URL to generate features so the tool works on ANY new URL
    X = df[url_col].apply(extract_features).apply(pd.Series)
    y = df[target_col]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest Model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Save everything
    joblib.dump(model, 'phishing_model.pkl')
    joblib.dump(X.columns.tolist(), 'features_list.pkl')
    
    print("SUCCESS: Model and Features saved!")
    print(f"Accuracy: {accuracy_score(y_test, model.predict(X_test)):.2%}")

if __name__ == "__main__":
    train_model('Phishing_URL.csv')
    pass
