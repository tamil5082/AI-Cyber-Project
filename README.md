# 🛡️ AI Phishing Guard

A Streamlit-based web application that uses AI to detect and classify phishing emails and messages.

## Features
- User authentication with login and sign-up
- Phishing email detection using transformer models
- Detection history tracking with SQLite database
- Real-time analysis with confidence scores

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishing-guard.git
cd phishing-guard
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
streamlit run app.py
```

Then open your browser to `http://localhost:8501`

## Requirements
- Python 3.8+
- Streamlit
- Transformers (Hugging Face)
- pandas
- sqlite3

## License
MIT
