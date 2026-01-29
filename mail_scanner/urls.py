from django.urls import path,include
from . import views
app_name = 'mail_scanner' 

urlpatterns = [
    # urls.py
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scan/', views.gmail_scan_view, name='scan'),
    path('results/', views.results_view, name='results'),
    path('download-report/', views.download_pdf_view, name='download_pdf'),]


