
import pyotp
import qrcode
import io
import base64
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import PermissionDenied

class TwoFactorAuth:
    """
    Two-Factor Authentication menggunakan TOTP (Time-based One-Time Password)
    """
    
    @staticmethod
    def generate_secret():
        """Generate a random secret key for TOTP"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_totp_uri(username, secret, issuer="BankApp"):
        """Generate TOTP URI for QR code"""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
    
    @staticmethod
    def generate_qr_code(totp_uri):
        """Generate QR code image from TOTP URI"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        
        return base64.b64encode(buffer.getvalue()).decode("utf-8")
    
    @staticmethod
    def verify_totp(secret, token):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

def check_permission(user, required_permission):
    """
    Check if user has the required permission based on user_type
    """
    permission_levels = {
        'customer': ['view_own_data', 'make_transaction'],
        'teller': ['view_own_data', 'make_transaction', 'view_customer_data', 'process_transaction'],
        'manager': ['view_own_data', 'make_transaction', 'view_customer_data', 'process_transaction', 
                   'view_reports', 'manage_users', 'view_audit_logs'],
    }
    
    if user.user_type not in permission_levels:
        return False
    
    return required_permission in permission_levels[user.user_type]

def permission_required(required_permission):
    """
    Decorator for views to ensure the user has the required permission
    """
    def decorator(view_func):
        def wrapped_view(request, *args, **kwargs):
            if not check_permission(request.user, required_permission):
                raise PermissionDenied("You don't have permission to access this resource")
            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator