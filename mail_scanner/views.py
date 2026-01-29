from django.shortcuts import render, redirect
from .utils import fetch_last_emails
from django.http import FileResponse
from django.contrib.auth.decorators import login_required
from .utils import get_gmail_service
from django.contrib.auth import logout
import json
from google_auth_oauthlib.flow import InstalledAppFlow
n=0
service=""
def login_view(request):
    return render(request, "mail_scanner/login.html")
def logout_view(request):
    logout(request)  # This clears the session and logs the user out
    return redirect('mail_scanner:login') 
@login_required(login_url='mail_scanner:login')
def dashboard(request):
   global service
   service = get_gmail_service(request.user)
   return render(request, "mail_scanner/dashboard.html")

def gmail_scan_view(request):
    if request.method=='POST':
        global n 
        n = int(request.POST.get('num_emails', 10))
        global em
        em,_= fetch_last_emails(n,service)
        return redirect("mail_scanner:results")
    return redirect("mail_scanner:dashboard")
 
   #return render(request,'mail_scanner/gmail.html',{'emails':emails})
@login_required(login_url='mail_scanner:login')
def results_view(request):
    global em
    return render(request, "mail_scanner/results.html", {"results": em})

def download_pdf_view(request):
    global n
    _, pdf_file = fetch_last_emails(n,service)
    return FileResponse(pdf_file, as_attachment=True, filename='email_threat_report.pdf')

# Create your views here.
