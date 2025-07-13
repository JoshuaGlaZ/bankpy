import logging
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from ..models import User, SecurityAuditLog, CustomerProfile
from ..security.auth import TwoFactorAuth
import uuid
import re

debug_logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Helper function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def register_view(request):
    """Handle user registration"""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        user_type = request.POST.get('user_type', 'customer')
        id_number = request.POST.get('id_number', '').strip()

        if len(password) < 8:
            messages.error(request, "Password harus memiliki minimal 8 karakter.")
            return render(request, 'register.html')

        if not re.search(r'[A-Z]', password):
            messages.error(request, "Password harus memiliki minimal 1 huruf kapital.")
            return render(request, 'register.html')

        if not re.search(r'[0-9]', password):
            messages.error(request, "Password harus memiliki minimal 1 angka.")
            return render(request, 'register.html')

        if not re.search(r'[^A-Za-z0-9]', password):
            messages.error(request, "Password harus memiliki minimal 1 karakter khusus.")
            return render(request, 'register.html')

        if not id_number or not id_number.isdigit() or len(id_number) != 16:
            messages.error(request, "Nomor KTP harus 16 digit angka.")
            return render(request, 'register.html')

        if password != confirm_password:
            messages.error(request, "Password tidak cocok.")
            return render(request, 'register.html')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username sudah digunakan.")
            return render(request, 'register.html')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email sudah digunakan.")
            return render(request, 'register.html')

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            user_type=user_type
        )

        if user_type == 'customer':
            account_number = f"ACC-{uuid.uuid4().hex[:8].upper()}"
            CustomerProfile.objects.create(
                user=user,
                account_number=account_number,
                id_number=request.POST.get('id_number', '').strip(),
                address=request.POST.get('address', '').strip(),
                date_of_birth=request.POST.get('date_of_birth')
            )

        # Log user registration event
        SecurityAuditLog.objects.create(
            user=user,
            event_type='register',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description=f"New user registration: {username}"
        )

        messages.success(request, "Registrasi berhasil. Silakan login.")
        return redirect('login')

    return render(request, 'register.html')


def login_view(request):
    """Handle user login"""
    if request.method == 'POST':
        identifier = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        totp_token = request.POST.get('totp_token')

        if settings.DEBUG:
            debug_logger.debug(f"[LOGIN DEBUG] identifier={identifier!r}, password={password!r}")
        user = authenticate(request, username=identifier, password=password)
        if user is None:
            try:
                email_user = User.objects.get(username=identifier)
                if email_user.check_password(password) and email_user.is_active:
                    user = email_user
                    debug_logger.debug(f"[LOGIN DEBUG] Fallback login via email succeeded for {identifier}")
            except User.DoesNotExist:
                debug_logger.debug(f"[LOGIN DEBUG] No user matches identifier={identifier}")

        # Check if user exists but is inactive
        if user is None and User.objects.filter(username=identifier).exists():
            inactive_user = User.objects.get(username=identifier)
            if inactive_user.check_password(password) and not inactive_user.is_active:
                # Log inactive account login attempt
                SecurityAuditLog.objects.create(
                    user=inactive_user,
                    event_type='failed_login',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description="Login attempt to inactive account",
                    additional_data={
                        "reason": "account_inactive",
                        "username": identifier,
                        "browser": request.META.get('HTTP_USER_AGENT', '').split(' ')[0],
                        "attempt_time": timezone.now().isoformat()
                    }
                )
                messages.error(request, "Akun Anda telah dinonaktifkan. Silakan hubungi petugas bank untuk informasi lebih lanjut.")
                return render(request, 'login.html')

        if user is not None:
            # Check if user account is active
            if not user.is_active:
                # Log inactive account login attempt
                SecurityAuditLog.objects.create(
                    user=user,
                    event_type='failed_login',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description="Login attempt to inactive account",
                    additional_data={
                        "reason": "account_inactive",
                        "username": identifier,
                        "browser": request.META.get('HTTP_USER_AGENT', '').split(' ')[0],
                        "attempt_time": timezone.now().isoformat()
                    }
                )
                messages.error(request, "Akun Anda telah dinonaktifkan. Silakan hubungi petugas bank untuk informasi lebih lanjut.")
                return render(request, 'login.html')
                
            # 2FA flow
            if user.two_factor_enabled and not totp_token:
                return render(request, 'login.html', {'username': identifier, 'require_2fa': True})

            if user.two_factor_enabled and totp_token:
                if not TwoFactorAuth.verify_totp(user.totp_secret, totp_token):
                    messages.error(request, "Kode autentikasi tidak valid.")
                    # Log failed 2FA attempt
                    SecurityAuditLog.objects.create(
                        user=user,
                        event_type='failed_login',
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        description="Invalid 2FA token",
                        additional_data={
                            "reason": "invalid_2fa",
                            "username": identifier,
                            "browser": request.META.get('HTTP_USER_AGENT', '').split(' ')[0]
                        }
                    )
                    return render(request, 'login.html', {'username': identifier, 'require_2fa': True})

            login(request, user)
            user.last_login = timezone.now()
            user.last_login_ip = get_client_ip(request)
            user.save()

            # Log successful login
            SecurityAuditLog.objects.create(
                user=user,
                event_type='login',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"User login: {user.username}",
                additional_data={
                    "user_type": user.user_type,
                    "two_factor_used": user.two_factor_enabled,
                    "login_time": timezone.now().isoformat(),
                    "browser_info": {
                        "user_agent": request.META.get('HTTP_USER_AGENT', ''),
                        "ip": get_client_ip(request)
                    }
                }
            )

            return redirect({
                'customer': 'customer_dashboard',
                'teller': 'teller_dashboard',
                'manager': 'manager_dashboard'
            }.get(user.user_type, 'home'))
        else:
            # Login gagal
            try:
                user_obj = User.objects.get(username=identifier)
                db_hash = user_obj.password
            except User.DoesNotExist:
                db_hash = None

            messages.error(request, "Username atau password salah.")

            if settings.DEBUG:
                debug_logger.debug(
                    "Failed login attempt details",
                    extra={
                        'identifier': identifier,
                        'password': password,
                        'db_hash': db_hash,
                    }
                )

            # Log failed login attempt
            SecurityAuditLog.objects.create(
                user=None,
                event_type='failed_login',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"Failed login attempt for identifier: {identifier}",
                additional_data={
                    "reason": "invalid_credentials",
                    "attempted_username": identifier,
                    "user_exists": User.objects.filter(username=identifier).exists(),
                    "browser": request.META.get('HTTP_USER_AGENT', '').split(' ')[0],
                    "attempt_time": timezone.now().isoformat()
                }
            )

    return render(request, 'login.html')


@login_required
def logout_view(request):
    """Handle user logout"""
    # Log user logout
    SecurityAuditLog.objects.create(
        user=request.user,
        event_type='logout',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        description=f"User logout: {request.user.username}" 
    )
    logout(request)
    messages.success(request, "Anda telah keluar dari sistem.")
    return redirect('login')


@login_required
def setup_2fa_view(request):
    """Setup two-factor authentication"""
    if request.method == 'POST':
        totp_token = request.POST.get('totp_token')
        secret = request.session.get('temp_totp_secret')

        if not secret:
            messages.error(request, "Sesi setup 2FA telah kedaluwarsa. Silakan coba lagi.")
            return redirect('setup_2fa')

        if TwoFactorAuth.verify_totp(secret, totp_token):
            user = request.user
            user.totp_secret = secret
            user.two_factor_enabled = True
            user.save()

            # Log 2FA enablement
            SecurityAuditLog.objects.create(
                user=user,
                event_type='security_update',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description="Enabled two-factor authentication",
                additional_data={
                    "security_feature": "2fa",
                    "action": "enabled",
                    "user_type": user.user_type,
                    "update_time": timezone.now().isoformat()
                }
            )

            request.session.pop('temp_totp_secret', None)
            messages.success(request, "Autentikasi dua faktor berhasil diaktifkan.")
            return redirect('profile')
        else:
            messages.error(request, "Kode autentikasi tidak valid. Silakan coba lagi.")

    secret = TwoFactorAuth.generate_secret()
    request.session['temp_totp_secret'] = secret
    totp_uri = TwoFactorAuth.generate_totp_uri(request.user.username, secret)
    qr_code = TwoFactorAuth.generate_qr_code(totp_uri)

    return render(request, 'setup_2fa.html', {
        'qr_code': qr_code,
        'secret': secret
    })


@login_required
def profile_view(request):
    """User profile view and management"""
    user = request.user
    profile = None
    if user.user_type == 'customer':
        try:
            profile = CustomerProfile.objects.get(user=user)
        except (CustomerProfile.DoesNotExist, Exception) as e:
            if 'DoesNotExist' in str(type(e)):
                account_number = f"ACC-{uuid.uuid4().hex[:8].upper()}"
                profile = CustomerProfile.objects.create(
                    user=user,
                    account_number=account_number,
                    id_number="",
                    address="",
                    date_of_birth=timezone.now()
                )
            else:
                # Decryption error, recreate profile with empty encrypted fields
                try:
                    profile = CustomerProfile.objects.filter(user=user).first()
                    if profile:
                        profile.id_number = ""
                        profile.address = ""
                        profile.save()

                        # Log encryption error
                        SecurityAuditLog.objects.create(
                            user=user,
                            event_type='security_error',
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            description="Encryption key mismatch, reset encrypted profile data"
                        )
                        messages.warning(request, "Terjadi masalah keamanan. Beberapa data profil telah direset.")
                    else:
                        # Create new profile
                        account_number = f"ACC-{uuid.uuid4().hex[:8].upper()}"
                        profile = CustomerProfile.objects.create(
                            user=user,
                            account_number=account_number,
                            id_number="",
                            address="",
                            date_of_birth=timezone.now()
                        )
                except Exception:
                    account_number = f"ACC-{uuid.uuid4().hex[:8].upper()}"
                    profile = CustomerProfile.objects.create(
                        user=user,
                        account_number=account_number,
                        id_number="",
                        address="",
                        date_of_birth=timezone.now()
                    )

    if request.method == 'POST':
        form_type = request.POST.get('form_type')
        
        if form_type == 'personal_info' and profile:
            id_number = request.POST.get('id_number', '')
            address = request.POST.get('address', '')
            date_of_birth = request.POST.get('date_of_birth')
            
            try:
                profile.id_number = id_number
                profile.address = address
                if date_of_birth:
                    profile.date_of_birth = date_of_birth
                profile.save()
                
                # Log profile update
                SecurityAuditLog.objects.create(
                    user=user,
                    event_type='profile_update',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description=f"User updated personal information"
                )
                
                messages.success(request, "Informasi pribadi berhasil diperbarui")
            except Exception as e:
                messages.error(request, "Terjadi kesalahan saat menyimpan data profil.")
                # Log the error
                SecurityAuditLog.objects.create(
                    user=user,
                    event_type='error',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description=f"Error updating profile: {str(e)}"
                )
            
        elif form_type == 'account_settings':
            email = request.POST.get('email', '')
            
            # Only update if email changed
            if email and email != user.email:
                user.email = email
                user.save()
                
                # Log the event
                SecurityAuditLog.objects.create(
                    user=user,
                    event_type='profile_update',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description=f"User updated email address"
                )
                
                messages.success(request, "Pengaturan akun berhasil diperbarui")
                
        elif form_type == 'change_password':
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if not user.check_password(current_password):
                messages.error(request, "Password saat ini tidak valid")
                return redirect('profile')
            
            if new_password != confirm_password:
                messages.error(request, "Password baru dan konfirmasi tidak cocok")
                return redirect('profile')
            
            user.set_password(new_password)
            user.save()
            
            # Log the event
            SecurityAuditLog.objects.create(
                user=user,
                event_type='password_change',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"User changed password"
            )
            
            messages.success(request, "Password berhasil diubah. Silakan login kembali.")
            return redirect('logout')
    
    context = {
        'profile': profile
    }
    
    return render(request, 'profile.html', context)
