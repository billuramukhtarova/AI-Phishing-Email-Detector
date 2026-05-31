import streamlit as st
import re
from urllib.parse import urlparse
import csv
from datetime import datetime
import os

st.title("AI Phishing Email Detector")

st.write("Paste an email text below and the system will analyze it.")

st.sidebar.title("About this project")
st.sidebar.write(
    "This project detects possible phishing emails using text analysis, "
    "sender checking, link checking, file upload, and history saving."
)

st.sidebar.subheader("Features")
st.sidebar.write("✅ Email text analysis")
st.sidebar.write("✅ Sender email check")
st.sidebar.write("✅ Link checker")
st.sidebar.write("✅ TXT file upload")
st.sidebar.write("✅ Analysis history")
st.sidebar.write("✅ AI-style explanation")

sender_email = st.text_input("Sender email:")

uploaded_file = st.file_uploader("Upload email text file (.txt)", type=["txt"])

file_text = ""

if uploaded_file is not None:
    file_text = uploaded_file.read().decode("utf-8")

email_text = st.text_area("Email text:", value=file_text, height=200)

suspicious_indicators = {
    "Urgency / pressure": [
        "urgent",
        "immediately",
        "limited time",
        "act now",
        "final warning",
        "last chance"
    ],
    "Account threats": [
        "account will be closed",
        "account suspended",
        "account locked",
        "unusual activity",
        "security alert"
    ],
    "Sensitive information request": [
        "password",
        "bank account",
        "credit card",
        "confirm your identity",
        "verify your account",
        "login details"
    ],
    "Suspicious action request": [
        "click here",
        "open the attachment",
        "download this file",
        "login immediately",
        "update your payment",
        "claim your reward"
    ]
}

trusted_domains = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "amazon.com"
]

if st.button("Analyze"):
    score = 0
    reasons = []

    # 1. Text analysis
    for category, phrases in suspicious_indicators.items():
        for phrase in phrases:
            if phrase in email_text.lower():
                score += 10
                reasons.append(f"{category}: '{phrase}' detected")

    # 2. Sender email check
    if sender_email.strip() == "":
        score += 5
        reasons.append("Sender email is missing")

    if "support" in sender_email.lower() and "gmail.com" in sender_email.lower():
        score += 15
        reasons.append("Suspicious sender: support email uses Gmail")

    if "-" in sender_email:
        score += 10
        reasons.append("Sender email contains dash")

    if sender_email.count(".") >= 3:
        score += 10
        reasons.append("Sender email has many dots")

    # 3. Link checker
    links = re.findall(r'https?://\S+', email_text)

    for link in links:
        parsed_url = urlparse(link)
        domain = parsed_url.netloc.lower()

        link_risk = 0

        if link.startswith("http://"):
            link_risk += 15
            reasons.append(f"Link uses unsafe HTTP protocol: {link}")

        if domain.count("-") >= 1:
            link_risk += 10
            reasons.append(f"Domain contains dash: {domain}")

        if len(domain) > 30:
            link_risk += 10
            reasons.append(f"Domain is unusually long: {domain}")

        if any(char.isdigit() for char in domain):
            link_risk += 5
            reasons.append(f"Domain contains numbers: {domain}")

        if any(brand in domain for brand in ["paypal", "google", "microsoft", "apple", "bank"]):
            if not any(domain.endswith(trusted) for trusted in trusted_domains):
                link_risk += 20
                reasons.append(f"Possible brand impersonation detected: {domain}")

        if link_risk == 0:
            reasons.append(f"Link looks normal: {domain}")
        else:
            score += link_risk
    
    # Limit score to 100
    if score > 100:
        score = 100

    # 4. Risk level
    if score >= 60:
        risk_level = "High Risk"
    elif score >= 30:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    # 5. Save analysis history
    history_file = "history.csv"
    file_exists = os.path.isfile(history_file)

    with open(history_file, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file, delimiter=";")

        if not file_exists:
            writer.writerow([
                "Date",
                "Sender Email",
                "Risk Score",
                "Risk Level"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sender_email,
            score,
            risk_level
        ])

    # 6. Show result
    if risk_level == "High Risk":
        st.error(f"{risk_level}: {score}/100")
    elif risk_level == "Medium Risk":
        st.warning(f"{risk_level}: {score}/100")
    else:
        st.success(f"{risk_level}: {score}/100")

    # 7. Show reasons
    st.subheader("Analysis Reasons")

    if reasons:
        for reason in reasons:
            st.write("•", reason)
    else:
        st.write("No suspicious indicators detected.")
    
    # 8. Basic AI explanation
    st.subheader("AI Explanation")

    if risk_level == "High Risk":
        st.write(
            "This email looks dangerous because it contains multiple phishing indicators. "
            "The user should not click any links, download files, or share personal information."
        )
    elif risk_level == "Medium Risk":
        st.write(
            "This email has some suspicious signs. The user should carefully check the sender, "
            "links, and message content before taking any action."
       )
    else:
        st.write(
         "This email looks relatively safe based on the current analysis, but the user should still verify unknown senders."
       )


# 9. Show history download
st.subheader("Analysis History")

if os.path.exists("history.csv"):
    with open("history.csv", "r", encoding="utf-8") as file:
        st.download_button(
            label="Download History CSV",
            data=file,
            file_name="history.csv",
            mime="text/csv"
        )
else:
    st.write("No analysis history yet.")