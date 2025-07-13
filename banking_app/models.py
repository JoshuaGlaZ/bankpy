from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
import uuid
from .security.crypto import encrypt_data, decrypt_data

class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('customer', 'Nasabah'),
        ('teller', 'Teller'),
        ('manager', 'Manajer'),
    )
    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )
    first_name = None
    last_name = None
    phone_number = None
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=50, null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.username} - {self.user_type}"

class EncryptedField(models.CharField):
    """Custom field untuk menyimpan data terenkripsi"""
    
    def __init__(self, *args, **kwargs):
        max_length = kwargs.get('max_length', 255)
        kwargs['max_length'] = max_length * 2  
        super().__init__(*args, **kwargs)
    
    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return decrypt_data(value)
    
    def to_python(self, value):
        if value is None:
            return value
        return decrypt_data(value) if isinstance(value, str) and len(value) > 0 else value
    
    def get_prep_value(self, value):
        if value is None:
            return value
        return encrypt_data(value)

class CustomerProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    account_number = models.CharField(max_length=20, unique=True)
    id_number = EncryptedField(max_length=50)  # KTP/SIM/Passport terenkripsi
    address = EncryptedField(max_length=255)
    date_of_birth = models.DateField()
    
    def __str__(self):
        return f"Profile: {self.user.username}"

class Account(models.Model):
    account_number = models.CharField(max_length=20, unique=True)
    customer = models.OneToOneField(User, on_delete=models.CASCADE, limit_choices_to={'user_type': 'customer'})
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.account_number} - {self.customer.username}"

class Transaction(models.Model):
    TRANSACTION_TYPE_CHOICES = (
        ('deposit', 'Setoran'),
        ('withdrawal', 'Penarikan'),
        ('transfer', 'Transfer'),
    )
    
    STATUS_CHOICES = (
        ('pending', 'Menunggu'),
        ('completed', 'Selesai'),
        ('failed', 'Gagal'),
        ('cancelled', 'Dibatalkan'),
    )
    
    transaction_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPE_CHOICES)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    timestamp = models.DateTimeField(default=timezone.now)
    description = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                   limit_choices_to={'user_type__in': ['teller', 'manager']})
    recipient_account = models.CharField(max_length=20, null=True, blank=True)  # Untuk transfer
    
    # Digital signature field
    digital_signature = models.TextField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.transaction_id} - {self.account.account_number} - {self.amount}"

class SecurityAuditLog(models.Model):
    EVENT_CHOICES = (
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('failed_login', 'Login Gagal'),
        ('password_change', 'Ganti Password'),
        ('sensitive_access', 'Akses Data Sensitif'),
        ('transaction', 'Transaksi'),
    )
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    event_type = models.CharField(max_length=20, choices=EVENT_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    description = models.TextField()
    additional_data = models.JSONField(null=True, blank=True, help_text="Additional contextual data for the event")
    
    def __str__(self):
        return f"{self.event_type} - {self.user} - {self.timestamp}"