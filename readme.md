#  Mail Scanner

Mail Scanner is a powerful email analysis tool that helps you manage your inbox efficiently. It scans your emails to identify **clean**, **suspicious**, and **malicious** messages. With **secure Google integration**, you can quickly access your emails while maintaining complete privacy.

---

## Features

### Security

- Detects **phishing attempts**
- Identifies **malware-related emails**
- Helps classify emails based on risk level

###  Smart Labeling

- Automatically **labels emails** as:
  - Clean
  - Suspicious
  - Malicious

###  PDF Reports

- **Download analysis results** as PDF files
- Useful for audits and reporting

### Machine Learning

- Uses ML naive bayes algorithme to analyze email content
- Generates `.pkl` model files for fast predictions
##  Tech Stack

- **Python**
- **Django** (backend & web interface)
- **Machine Learning** (custom models)
- **Google OAuth** (secure email access)
- **virustotal** 
##  Installation 
Follow these steps to set up the project locally.

### 1-Clone the repository

```bash
git clone https://github.com/marwa-en/mail-scanner.git
```

### 2-Create a virtual environment

```bash
python -m venv venv
```

### 3-Activate the virtual environment (Windows)

```powershell
venv/Script/Activate.ps1
```

### 4-Install dependencies

```bash
pip install -r requirements.txt
```
##  setup
## Configure the .env file:
###  Google OAuth 2.0 Setup:
    Create a OAuth 2.0 Client IDs 
    Copy the client_id and client_secret in .env vars:
     GOOGLE_OAUTH_CLIENT_ID
     GOOGLE_OAUTH_CLIENT_SECRET
##  Django SECRET_KEY Configuration:

### Generating a SECRET_KEY
   ```bash
    python -c "from django.core.management.utils import get_random_secret_key; print(f'SECRET_KEY={get_random_secret_key()}')"
   ```
    Copy the secret_key in .env var:
     SECRET

##  Machine Learning Setup

Before running the web application, generate the ML model files:
search for a dataset mixed with spam and normal mails
inject it in the code of ml.py

```bash
python ml.py
```

 This will create the required `.pkl` files used by the application.

---

## Database Setup

Apply database migrations:

```bash
python manage.py migrate
```

---

##  Run the Application

Start the Django development server:

```bash
python manage.py runserver
```

Then open your browser and go to:

```
http://127.0.0.1:8000/
```

---

## Google Integration

- Uses **Google OAuth** for secure email access
- No email data is stored permanently
- Privacy-first design

---

##  Project Outputs

- `.pkl` → Trained ML models
- `.pdf` → Downloadable scan reports
- Email labels → Clean / Suspicious / Malicious
