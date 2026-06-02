# AI Phishing Email Detector

This project is a cybersecurity tool that detects possible phishing emails.

## Features

- Email text analysis
- Sender email check
- Link checker
- TXT file upload
- Analysis history
- AI-style explanation

## Tools Used

- Python
- Streamlit
- Regular Expressions
- URL Parsing
- CSV / Excel history

## How It Works

The system analyzes the email text, sender address, and links.  
It gives a risk score and explains why the email may be suspicious.

## How to Run

```bash
pip install -r requirements.txt
streamlit run app.py

# If we are in the Power Shell(PS). We have to go venv

```PS
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate

```(venv)PS
python -m pip install streamlit
python -m streamlit run app.py
