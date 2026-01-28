import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
from model import extract_features # Import our feature function

# Load the saved model and feature list
try:
    model = joblib.load('phishing_model.pkl')
    features_list = joblib.load('features_list.pkl')
except:
    st.error("Model files not found. Please run 'python model.py' first!")

st.set_page_config(
    page_title="SOC Phishing URL Detector", 
    page_icon="🛡️", 
    layout="wide",  # This makes it occupy the full width
    initial_sidebar_state="collapsed"
)

TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'github.com', 'apple.com', 'wikipedia.org','login']

def is_whitelisted(url_input):
    domain = urlparse(url_input).netloc.lower()
    # Check if the domain ends with any of our trusted names (handles subdomains)
    return any(domain.endswith(trusted) for trusted in TRUSTED_DOMAINS)

st.markdown("""
    <style>
    .block-container {
        padding-top: 2.5rem;
        padding-bottom: 1rem;
        padding-left: 5rem;
        padding-right: 5rem;
        max-width: 100%;
    }
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #FF4B4B;
        color: white;
    }
    .reportview-container .main .block-container {
        padding-top: 2rem;
    }
    /* Professional Alert Styling */
    .risk-header {
        padding: 10px 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        display: inline-block;
    }
    .high-risk {
        background-color: rgba(255, 75, 75, 0.1);
        border: 1px solid #FF4B4B;
        color: #FF4B4B;
    }
    .safe {
        background-color: rgba(46, 204, 113, 0.1);
        border: 1px solid #2ECC71;
        color: #2ECC71;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Mini SOC Phishing URL Detector")
st.markdown("---")

left_col, right_col = st.columns([1, 1.5], gap="large")

with left_col:
    st.subheader("🕵️ Investigation Panel")
    st.info("Input the suspicious URL below to begin forensic extraction.")
    url_input = st.text_input("Target URL:", placeholder="http://amaz0n-login.com")
    
    analyze_btn = st.button("Run Forensic Analysis", use_container_width=True)
    st.markdown("---")

with right_col:
    st.subheader("📊 Analysis Results")

    if analyze_btn:
        if url_input:
            if is_whitelisted(url_input):
                st.success("✅ Safe: This is a verified Trusted Domain (Whitelist).")
                st.metric("Phishing Risk Score", "0.00%")
            else:
                # 1. Extract features from the input
                feat_dict = extract_features(url_input)
                input_df = pd.DataFrame([feat_dict])[features_list]
                
                # 2. Predict
                # Note: In PhiUSIIL, 0 = Phishing, 1 = Legitimate
                prediction = model.predict(input_df)[0]
                prob = model.predict_proba(input_df)[0] # [Prob of 0, Prob of 1]
                phish_prob = prob[0]

                # --- SOC HEURISTIC OVERRIDE ---
                # If it has "amaz0n" style features, we force the risk up
                if feat_dict.get('digits_in_domain', 0) > 0 and "amaz" in url_input.lower():
                    phish_prob = max(phish_prob, 0.95) # Force at least 90% risk
                
                if phish_prob > 0.5:
                    st.markdown(f'<div class="risk-header high-risk">🚨 <b>HIGH RISK DETECTED</b></div>', unsafe_allow_html=True)

                    m_col1, m_col2 = st.columns(2)
                    m_col1.metric("Threat Probability", f"{phish_prob * 100:.2f}%")
                    
                    with m_col2:
                        st.write("**Risk Indicators:**")
                        if feat_dict.get('digits_in_domain', 0) > 0: st.markdown("- Found digits in domain")
                        if feat_dict.get('is_https') == 0: st.markdown("- Unencrypted protocol (HTTP)")
                        if "amaz" in url_input.lower(): st.markdown("- Potential brand spoofing")
                        if feat_dict['num_subdomains'] > 1: st.write("•  High subdomain count (Obfuscation risk).")
                        if feat_dict['num_suspicious_words'] > 0: st.write(f"- 🚩  Contains {feat_dict['num_suspicious_words']} sensitive keywords.")
                    
                else:
                    st.markdown(f'<div class="risk-header safe">✅ <b>URL APPEARS LEGITIMATE</b></div>', unsafe_allow_html=True)                    
                    st.metric("Threat Probability", f"{phish_prob * 100:.2f}%", delta_color="inverse")
                    st.write("The URL structure does not match known malicious patterns in the PhiUSIIL dataset.")
                                
                with st.expander("🔍 View Raw Forensic Features", expanded=False):
                    st.dataframe(input_df.style.highlight_max(axis=0, props='color:white;'), use_container_width=True)

        else:

            st.warning("Please enter a URL.")
