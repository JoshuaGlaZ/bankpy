from django.urls import path
from .views import auth_views, customer_views, teller_views, manager_views

urlpatterns = [
    # Authentication URLs
    path('login/', auth_views.login_view, name='login'),
    path('logout/', auth_views.logout_view, name='logout'),
    path('register/', auth_views.register_view, name='register'),
    path('setup-2fa/', auth_views.setup_2fa_view, name='setup_2fa'),
    path('profile/', auth_views.profile_view, name='profile'),
    
    # Customer URLs
    path('dashboard/', customer_views.customer_dashboard, name='customer_dashboard'),
    path('transactions/', customer_views.transaction_history, name='transaction_history'),
    path('transfer/new/', customer_views.new_transfer, name='new_transfer'),
    path('transaction/<uuid:transaction_id>/pdf/', customer_views.download_transaction_pdf, name='download_transaction_pdf'),
    
    # Teller URLs
    path('teller/', teller_views.teller_dashboard, name='teller_dashboard'),
    path('teller/search/', teller_views.search_customer, name='search_customer'),
    path('teller/customer/<int:customer_id>/', teller_views.customer_detail, name='customer_detail'),
    path('teller/customer/<int:customer_id>/create-account/', teller_views.create_account, name='create_account'),
    path('teller/customer/<int:customer_id>/toggle-status/', teller_views.toggle_customer_status, name='toggle_customer_status'),
    path('teller/process-withdrawal/', teller_views.process_withdrawal, name='process_withdrawal'),
    path('teller/transaction/<uuid:transaction_id>/process/', teller_views.process_transaction, name='process_transaction'),
    
    # Manager URLs
    path('manager/', manager_views.manager_dashboard, name='manager_dashboard'),
    path('manager/audit-logs/', manager_views.audit_log_view, name='audit_logs'),
    path('manager/audit-logs/detail/', manager_views.audit_log_detail, name='audit_log_detail'),
    path('manager/export-transactions/', manager_views.export_transaction_report, name='export_transaction_report'),
    
    # Home page
    path('', auth_views.login_view, name='home'),  # Redirect to login page as default
]