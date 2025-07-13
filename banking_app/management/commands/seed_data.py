import random
import uuid
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from banking_app.models import User, CustomerProfile, Account, Transaction, SecurityAuditLog
from banking_app.security.auth import TwoFactorAuth
from banking_app.security.crypto import encrypt_data
from faker import Faker
from decimal import Decimal

fake = Faker('id_ID')  # Indonesian locale

class Command(BaseCommand):
    help = 'Seeds the database with realistic data'

    def add_arguments(self, parser):
        parser.add_argument('--customers', type=int, default=20, help='Number of customers to create')
        parser.add_argument('--tellers', type=int, default=5, help='Number of tellers to create')
        parser.add_argument('--managers', type=int, default=2, help='Number of managers to create')
        parser.add_argument('--transactions', type=int, default=100, help='Number of transactions to create')
        parser.add_argument('--clear', action='store_true', help='Clear existing data before seeding')
    
    def handle(self, *args, **options):
        if options['clear']:
            self.clear_data()
            
        # Create admin superuser if doesn't exist
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser(
                username='admin',
                email='admin@bankingsystem.com',
                password='admin12345',
                user_type='manager',
                two_factor_enabled=True,
                totp_secret=TwoFactorAuth.generate_secret()
            )
            self.stdout.write(self.style.SUCCESS('Admin superuser created.'))
        
        # Create sample users
        customers = self.create_customers(options['customers'])
        tellers = self.create_tellers(options['tellers'])
        managers = self.create_managers(options['managers'])
        
        # Create sample transactions
        self.create_transactions(customers, tellers, managers, options['transactions'])
        
        self.stdout.write(self.style.SUCCESS('Seeding completed!'))
    
    def clear_data(self):
        SecurityAuditLog.objects.all().delete()
        Transaction.objects.all().delete()
        Account.objects.all().delete()
        CustomerProfile.objects.all().delete()
        User.objects.exclude(username='admin').delete()
        self.stdout.write(self.style.SUCCESS('Cleared existing data.'))
    
    def create_customers(self, count):
        customers = []
        
        for i in range(count):
            # Create a customer user
            username = f"{fake.first_name().lower()}{random.randint(1, 999)}"
            
            user = User.objects.create(
                username=username,
                email=f"{username}@example.com",
                password=make_password('password123'),
                user_type='customer',
                phone_number=fake.phone_number(),
                two_factor_enabled=random.choice([True, False]),
                last_login_ip=fake.ipv4(),
                date_joined=fake.date_time_between(start_date='-2y', end_date='now', tzinfo=timezone.get_current_timezone())
            )
            
            if user.two_factor_enabled:
                user.totp_secret = TwoFactorAuth.generate_secret()
                user.save()
            
            # Create customer profile
            account_number = f"ACC-{uuid.uuid4().hex[:8].upper()}"
            
            # Direct model creation for encrypted fields
            profile = CustomerProfile(
                user=user,
                account_number=account_number,
                date_of_birth=fake.date_of_birth(minimum_age=18, maximum_age=70)
            )
            
            # Set encrypted fields directly (will be encrypted by the model's save method)
            profile.id_number = str(fake.random_number(digits=16)) 
            profile.address = fake.address()
            profile.save()
            
            # Create account with random balance
            balance = random.uniform(1000000, 100000000)  # Between 1 Million and 100 Million IDR
            account = Account.objects.create(
                account_number=account_number,
                customer=user,
                balance=Decimal(str(balance)),
                is_active=True,
                created_at=user.date_joined
            )
            
            customers.append(user)
            self.stdout.write(f"Created customer: {username} with account {account_number}")
        
        return customers
    
    def create_tellers(self, count):
        tellers = []
        
        for i in range(count):
            # Create teller users
            username = f"teller{i+1}"
            
            user = User.objects.create(
                username=username,
                email=f"{username}@bankingsystem.com",
                password=make_password('teller123'),
                user_type='teller',
                phone_number=fake.phone_number(),
                two_factor_enabled=True,
                totp_secret=TwoFactorAuth.generate_secret(),
                last_login_ip=fake.ipv4(),
                date_joined=fake.date_time_between(start_date='-1y', end_date='now', tzinfo=timezone.get_current_timezone())
            )
            
            tellers.append(user)
            self.stdout.write(f"Created teller: {username}")
        
        return tellers
    
    def create_managers(self, count):
        managers = []
        
        for i in range(count):
            # Create manager users
            username = f"manager{i+1}"
            
            user = User.objects.create(
                username=username,
                email=f"{username}@bankingsystem.com",
                password=make_password('manager123'),
                user_type='manager',
                phone_number=fake.phone_number(),
                two_factor_enabled=True,
                totp_secret=TwoFactorAuth.generate_secret(),
                last_login_ip=fake.ipv4(),
                date_joined=fake.date_time_between(start_date='-1y', end_date='now', tzinfo=timezone.get_current_timezone())
            )
            
            managers.append(user)
            self.stdout.write(f"Created manager: {username}")
        
        return managers
    
    def create_transactions(self, customers, tellers, managers, count):
        # Transaction types and statuses
        transaction_types = ['deposit', 'withdrawal', 'transfer']
        statuses = ['completed', 'pending', 'failed', 'cancelled']
        weights = [0.7, 0.2, 0.05, 0.05]  # Most transactions are completed
        
        accounts = Account.objects.filter(customer__in=customers)
        staff = tellers + managers
        
        for i in range(count):
            # Select random account
            account = random.choice(accounts)
            
            # Determine transaction type
            transaction_type = random.choice(transaction_types)
            
            # Determine amount based on type
            if transaction_type == 'deposit':
                amount = random.uniform(100000, 5000000)  # Deposit amount
            elif transaction_type == 'withdrawal':
                amount = random.uniform(50000, min(1000000, float(account.balance)))  # Withdrawal amount
            else:  # transfer
                amount = random.uniform(10000, min(2000000, float(account.balance)))  # Transfer amount
            
            # Round to 2 decimal places
            amount = round(amount, 2)
            
            # Select random recipient for transfers
            recipient_account = None
            if transaction_type == 'transfer':
                potential_recipients = Account.objects.exclude(id=account.id)
                if potential_recipients.exists():
                    recipient_account = random.choice(potential_recipients).account_number
            
            # Select staff member who processed it
            processed_by = random.choice(staff) if random.random() < 0.8 else None
            
            # Determine status (weighted random choice)
            status = random.choices(statuses, weights=weights, k=1)[0]
            
            # Generate random timestamp within last year
            timestamp = fake.date_time_between(start_date='-1y', end_date='now', tzinfo=timezone.get_current_timezone())
            
            # Create transaction
            transaction = Transaction.objects.create(
                account=account,
                transaction_type=transaction_type,
                amount=Decimal(str(amount)),  # Convert to Decimal
                timestamp=timestamp,
                description=self.generate_transaction_description(transaction_type, recipient_account),
                status=status,
                processed_by=processed_by,
                recipient_account=recipient_account,
            )
            
            # Update account balance for completed transactions
            if status == 'completed':
                if transaction_type == 'deposit':
                    account.balance += Decimal(str(amount))
                elif transaction_type in ['withdrawal', 'transfer']:
                    account.balance -= Decimal(str(amount))
                account.save()
                
                # Log security audit for completed transactions
                SecurityAuditLog.objects.create(
                    user=account.customer,
                    event_type='transaction',
                    timestamp=timestamp,
                    ip_address=fake.ipv4(),
                    user_agent=fake.user_agent(),
                    description=f"{transaction_type.capitalize()} of {amount:,.2f} IDR",
                    additional_data={
                        "transaction_id": str(transaction.transaction_id),
                        "transaction_type": transaction_type,
                        "amount": str(amount),
                        "status": status,
                        "account_number": account.account_number,
                        "processed_by": processed_by.username if processed_by else None,
                        "recipient_account": recipient_account,
                        "transaction_details": {
                            "timestamp": timestamp.isoformat(),
                            "ip_address": fake.ipv4(),
                            "device": random.choice(["mobile", "web", "atm", "branch"])
                        }
                    }
                )
        
        self.stdout.write(f"Created {count} transactions.")
    
    def generate_transaction_description(self, transaction_type, recipient_account):
        if transaction_type == 'deposit':
            return random.choice([
                "Setoran tunai",
                "Setoran via ATM",
                "Deposit dari gaji",
                "Deposit dari penjualan",
                "Setoran bisnis"
            ])
        elif transaction_type == 'withdrawal':
            return random.choice([
                "Penarikan tunai",
                "Penarikan via ATM",
                "Penarikan untuk kebutuhan bulanan",
                "Penarikan untuk bisnis",
                "Penarikan darurat"
            ])
        else:  # transfer
            return random.choice([
                f"Transfer ke {recipient_account}",
                f"Pembayaran ke {recipient_account}",
                f"Transfer bulanan ke {recipient_account}",
                f"Biaya pendidikan ke {recipient_account}",
                f"Transfer bisnis ke {recipient_account}"
            ]) 