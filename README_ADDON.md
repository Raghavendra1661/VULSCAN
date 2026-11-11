## Project structure

```text
VULSCAN/
├── app.py
├── requirements.txt
├── scanner/
│   ├── __init__.py
│   ├── ports.py
│   ├── report.py
│   ├── versions.py
│   └── web_checks.py
├── templates/
│   ├── index.html
│   └── report.html
└── static/
    └── style.css
```

## Run locally

1. Create and activate a Python virtual environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Start the app: `python app.py`
4. Open `http://127.0.0.1:5000`.

Only scan systems you own or have explicit permission to test. This project performs basic checks and is not a substitute for a professional vulnerability assessment.
