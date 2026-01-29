import os, base64, joblib, json
from email.parser import Parser
from email import policy
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import mimetypes
from social_django.models import UserSocialAuth
import magic
from bs4 import BeautifulSoup
import requests 
from dotenv import load_dotenv
import re
from fpdf import FPDF
from io import BytesIO
ATTACHMENT_DIR = "attachments"
PERMISSION = ['https://www.googleapis.com/auth/gmail.modify']
load_dotenv()
from social_django.models import UserSocialAuth
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

def get_gmail_service(user):
    try:
        social = user.social_auth.get(provider='google-oauth2')
        credentials = Credentials(
            token=social.extra_data['access_token'],
            refresh_token=social.extra_data.get('refresh_token'),
            token_uri='https://oauth2.googleapis.com/token',
            client_id=os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
        )
        
        service = build('gmail', 'v1', credentials=credentials)
        return service
    except Exception as e:
        print(f"Error: {e}")
        return None
def save_attachment(part, filename):
    if not os.path.exists(ATTACHMENT_DIR):
        os.makedirs(ATTACHMENT_DIR)
    filepath = os.path.join(ATTACHMENT_DIR, filename)
    payload = part.get_payload(decode=True)
    if payload:
        with open(filepath, 'wb') as f:
            f.write(payload)
    return filepath
def keyword(body, subject):
    model = joblib.load("spam_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    email_text = subject.strip() + " " + body.strip()
    email_vec = vectorizer.transform([email_text])
    prediction = model.predict(email_vec)[0]
    if prediction==1:
       return True,"SPAM" 
    else:
        return False,"HAM"
#check if the attachement has double extension
def double_extension(filename):
    parts = filename.lower().split('.')
    if len(parts) < 3:
        return False  # Not enough dots for double extension

    # Extract last two extensions (e.g., 'pdf' and 'exe' in 'file.pdf.exe')
    last_ext = '.' + parts[-1]
    second_last_ext = '.' + parts[-2]

    # Check if last extension is dangerous AND second last is a known common extension
    dangerous_exts = {'.exe', '.scr', '.bat', '.js', '.vbs', '.cmd', '.ps1', '.pif', '.cpl'}
    if last_ext in dangerous_exts  or second_last_ext in dangerous_exts:
        return True
    return False

#check the malicious extensions
def malicious_extension(filename):
     dangerous = {'.exe', '.scr', '.bat', '.js', '.vbs', '.cmd', '.ps1', '.pif', '.cpl'}
     for ext in dangerous:
          if filename.lower().endswith(ext):
               return True
          else:
               return False
#Matching with MIME
#get the mime type
def get_mime_type(part,filename):
     filepath=save_attachment(part,filename)
     mime=magic.from_file(filepath,mime=True)
     return mime 
#comare the mime_type and the extension    
def match_mime(part,filename):
     #the mimetypes return a tuple (ex:app/pdf)
     #the comma is to separate these two values to g_mime and in python _ means ignoring the seconde variable
     g_mime,_=mimetypes.guess_type(filename)
     detected_mime=get_mime_type(part,filename)
     if g_mime is None:
          return False
     return g_mime==detected_mime
def file_treat(part,filename):
     if double_extension(filename):
           return True, "Double extension detected"
     if malicious_extension(filename):
          return True, "Dangerous file extension"
     if not match_mime(part,filename):
         return True, f"MIME type mismatch"
     return False, "File looks safe"
#RL SCANING USING VIRTUALTOTAL
#1) url extraction
   #a)extract url from text:
def extracturls(text):
    url_pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    urls = re.findall(url_pattern, text)
    return urls
    #b)extract url from html:
def extract_urls_from_html(html):
    # Extract URLs from <a href="..."> using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    return [a['href'] for a in soup.find_all('a', href=True)]
    #c)join ann of the extractions
def extract_url(body):
    text=extracturls(body)
    html=extract_urls_from_html(body)
    all_urls = list(set(text + html))  # Remove duplicates
    return all_urls
#url detection:
def scanurl(url):
    # URL must be base64-encoded (without padding)
     encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    # Get scan results (must POST the URL first if it's not known)
     response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    )

     if response.status_code == 200: #200 means the request is done successfully
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        total=sum(stats.values())
        mal= stats.get("malicious",0)
        score= mal/ total if total>0 else 0.0
        score= round(score,2)
        risk = "malicious" if stats['malicious']>0 else "suspicious" if stats['suspicious'] else "safe"
        return {
             "url": url,
             "malicious": stats['malicious'],
             "suspicious": stats['suspicious'],
             "harmless": stats['harmless'],
              "risk": risk
        },score
     else:
        return {"error": response.text}, None
def calculate(is_spam, has_malicious_file, has_malicious_url):
    weights = {
        'spam': 0.5,
        'file': 0.25,
        'url': 0.25
    }

    total = 0
    if is_spam:
        total += weights['spam']
    if has_malicious_file:
        total += weights['file']
    if has_malicious_url:
        total += weights['url']

    # Normalize contributions
    spam_percent = (weights['spam'] / total * 100) if is_spam else 0
    file_percent = (weights['file'] / total * 100) if has_malicious_file else 0
    url_percent = (weights['url'] / total * 100) if has_malicious_url else 0

    return round(spam_percent, 1), round(file_percent, 1), round(url_percent, 1)
class PDF(FPDF):

    def header(self):
        self.set_font("Helvetica", 'B', 14)
        self.cell(0, 10, " Email Threat Analysis Report", ln=True, align='C')
        self.ln(8)

    def section_title(self, title):
        self.set_font("Helvetica", 'B', 12)
        self.set_fill_color(230, 230, 250)
        self.cell(0, 8, title, ln=True, fill=True)
        self.ln(2)

    def table_row(self, cols, col_widths, align='L'):
        self.set_font("Helvetica", '', 10)
        for i, col in enumerate(cols):
            self.cell(col_widths[i], 8, str(col), border=1, align=align)
        self.ln()
def generate(pdf,email_data, file_scan, url_results, spam_results, filename="email_detailed_report.pdf"):
    # === Summary ===
    pdf.add_page()
    pdf.section_title(" Summary")
    summary_text = (
        f"Subject: {email_data['subject']}\n"
        f"From: {email_data['sender']}\n"
        f"Date: {email_data['date']}\n"
        f"SPF: {email_data['SPF']}\n"
        f"DKIM: {email_data['DKIM']}\n"
        f"DMARC: {email_data['DMARC']}\n"
        f"Score: {email_data['score']}\n"
        f"Final Decision: {email_data['decision']}\n"
    )
    pdf.set_font("Helvetica", '', 11)
    summary_text = clean_text(summary_text)
    pdf.multi_cell(0, 7, summary_text)
    pdf.ln()

    # === 1. File Scan Results ===
    pdf.section_title(" File Scan Results")
    col_widths = [10, 50, 40, 25, 65]
    headers = ["#", "Filename", "Type", "Status", "Reason"]
    pdf.table_row(headers, col_widths)
    if file_scan:
     for  i,file in enumerate(file_scan, start=1):
        reason_clean = clean_text(file['reason'])
        filename_clean=clean_text(file['filename'])
        row = [
            i,
            reason_clean,
            filename_clean,
            "Suspicious" if file['is_suspicious'] else "Safe",
            file['reason']
        ]
        pdf.table_row(row, col_widths)

    # === 2. URL Scan Results ===
    pdf.section_title("URL Analysis")
    col_widths = [10, 90, 30, 20, 20, 20]
    headers = ["#", "URL", "Risk", "Mal", "Susp", "Harmless"]
    pdf.table_row(headers, col_widths)
    if url_results:
     for i, url in enumerate(url_results, start=1):
        row = [
            i,
            url['url'],
            url['risk'],
            str(url['malicious']),
            str(url['suspicious']),
            str(url['harmless']),
        ]
        pdf.table_row(row, col_widths)

    # === 3. Spam Detection ===
    pdf.section_title("Spam Classification")
    col_widths = [60, 120]
    data = [
        ("Is Spam", "Yes" if spam_results['is_spam'] else "No"),
    ]
    for row in data:
        pdf.table_row(row, col_widths)

def g(all_emails, all_files, all_urls, all_spams, output_filename="email_summary_report.pdf"):
    pdf = PDF()
    for index, (email_data, file_scan, url_scan, spam_result) in enumerate(zip(all_emails, all_files, all_urls, all_spams), start=1):
        generate(pdf, email_data, file_scan, url_scan, spam_result)
    pdf_buffer= BytesIO()
    pdf.output(pdf_buffer)
    pdf_buffer.seek(0)
    return pdf_buffer
def get_or_create_label(service, label_name):
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    for label in labels:
        if label['name'].lower() == label_name.lower():
            return label['id']
    
    # Create label if not found
    label_body = {
        'name': label_name,
        'labelListVisibility': 'labelShow',
        'messageListVisibility': 'show'
    }
    created_label = service.users().labels().create(userId='me', body=label_body).execute()
    return created_label['id']
def add_label_to_email(service, msg_id, label_id):
    body = {
        'addLabelIds': [label_id],
        'removeLabelIds': []  # You can add system labels like 'INBOX' if you want to move emails
    }
    service.users().messages().modify(userId='me', id=msg_id, body=body).execute()
def clean_text(text):
    replacements = {
        "’": "'",      # right single quote → apostrophe
        "“": '"',      # left double quote
        "”": '"',      # right double quote
        "–": "-",      # en dash
        "—": "-",      # em dash
        "‑": "-",      # non-breaking hyphen ← THIS ONE!
        "\u00a0": " ", # non-breaking space
        "\u200b": "",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text

def fetch_last_emails(n,service):
    results = service.users().messages().list(userId='me', maxResults=n).execute()
    messages = results.get('messages', [])
    email_results = []
    dat=[]
    ff=[]
    uuu=[]
    sss=[]
    for msg in messages:
        filee=[]
        suspicious= False
        filepath="no file"
        sus= False
        ml=0
        email=0
        security=0
        url=0
        file=0
        good=100
        content_type="no type"
        file_result=""
        msg_id = msg['id']
        m = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        raw_data = m['raw']
        raw_str = base64.urlsafe_b64decode(raw_data).decode('utf-8')
        parser = Parser(policy=policy.default)
        mm = parser.parsestr(raw_str)
        subject = mm['Subject']
        sender = mm['From']
        date=mm['Date']
        SPF=mm['Received-SPF']
        result=mm['Authentication-Results']
        DKIM= result.split('dkim=')[1].split()[0]
        DMARC= result.split('dmarc=')[1].split()[0]
        body = ""
        if mm.is_multipart():
            for part in mm.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                if 'attachment' not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                        break
                
                for i, p in enumerate(part.walk()):
                          filename=p.get_filename()
                          if filename:
                                       content_type=p.get_content_type()
                                       filepath=save_attachment(p,filename)
                                       file_treat(p,filename)
                                       suspicious, reason = file_treat(p, filename)
                                       filepath=save_attachment(p,filename)
                                       if suspicious:
                                           file_result= f"Suspicious file blocked: {filename} {reason}"
                                           os.remove(filepath)  # Or quarantine instead
                                           file+=1
                                           email+=25
                                           security+=1
                                           filepath="no file"
                                       else:
                                          file_result= f" File passed checks: {filename}"
                                       filee.append({"filename":filename, "type":content_type,"is_suspicious":suspicious,"reason":reason})                 
        else:
            payload = mm.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
        a,result = keyword(body, subject)
        if a:
             ml+=50
             security+=1
             email+=50
             o="spam"
        else:
            o="ham"
        spam_r={
             "is_spam":a
        }
        urls=extract_url(body)
        c=0  
        url_scan=[]
        uu=[]
        for i in urls:
             c+=1
             f,r=scanurl(i)
             if f.get("malicious",0)>0 or f.get("suspicious",0)>0 :
                  url+=1
                  security+=1
                  email+=25
                  sus=True
             url_scan.append({f"{c} : {f.get("risk")}"})
             uu.append({"url":f.get("url"),"risk":f.get("risk"),"malicious":f.get("malicious"),"suspicious":f.get("suspicious"),"harmless":f.get("harmless")})

        if  c>0:
             x=True
        else:
             x=False
        score=good-email
        if url_scan== []:
             url_scan=["no url to scan"]
        if file_result=="":
             file_result="no file to check"
        if score==100:
             email_label=" The mail is ham there is no malicious issues"
             label_id = get_or_create_label(service, "Clean_Mail")
             add_label_to_email(service, msg_id, label_id)
        elif score<100 and score>=50:
             email_label=" The mail has suspicious issues"
             label_id = get_or_create_label(service, "Suspicious_Mail")
             add_label_to_email(service, msg_id, label_id)
        else:
             email_label="The mail has malicious issues"
             label_id = get_or_create_label(service, "Malicious_Mail")
             add_label_to_email(service, msg_id, label_id)
        score= f"{score}%"
        email_data={'subject':subject,'sender':sender,'date':date,'SPF':SPF,'DKIM':DKIM,'DMARC':DMARC,'score':score,'decision':email_label}
        email_results.append({
            "sender": sender,
            "subject": subject,
            "result": result,
            "body": body[:300] + "..." if len(body) > 300 else body,
            "file": file_result,
            "url": url_scan,
            "email_score": email,
            "email_label": email_label,
            "ml_scan":o
        })
        dat.append(email_data)
        uuu.append(uu)
        ff.append(filee)
        sss.append(spam_r)
    pdf_buffer=g(dat[:n], ff[:n], uuu[:n], sss[:n])
    return email_results,pdf_buffer
