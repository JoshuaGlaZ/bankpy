
import re
from django.core.exceptions import ValidationError

def validate_id_number(value):
    """
    Validate Indonesian ID number (KTP)
    KTP consists of 16 digits
    """
    if not re.match(r'^\d{16}$', value):
        raise ValidationError('Nomor KTP harus terdiri dari 16 digit angka')
    
    return value

def validate_account_number(value):
    """
    Validate bank account number format
    """
    if not re.match(r'^ACC-[A-Z0-9]{8}$', value):
        raise ValidationError('Format nomor rekening tidak valid')
    
    return value

def validate_phone_number(value):
    """
    Validate Indonesian phone number format
    """
    # Remove spaces and non-digit characters
    clean_number = re.sub(r'\D', '', value)
    
    # Check if 08 or +62 (converted to 62)
    if not (clean_number.startswith('08') or clean_number.startswith('62')):
        raise ValidationError('Nomor telepon harus diawali dengan 08 atau +62')
    
    # Check length (10-13 digits)
    if len(clean_number) < 10 or len(clean_number) > 13:
        raise ValidationError('Nomor telepon harus terdiri dari 10-13 digit')
    
    return value

def sanitize_input(value):
    """
    Sanitize user input to prevent XSS and SQL injection
    """
    if value is None:
        return None
    
    if not isinstance(value, str):
        value = str(value)
    
    # Remove potentially dangerous characters
    value = re.sub(r'[<>&\'";()]', '', value)
    
    # Remove SQL injection patterns
    value = re.sub(r'(\b(select|insert|update|delete|drop|alter|exec|union|where|from)\b)', 
                  lambda match: match.group(1).upper(), value, flags=re.IGNORECASE)
    
    return value