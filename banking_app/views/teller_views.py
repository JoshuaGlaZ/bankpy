from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.contrib import messages
from ..models import Account, Transaction, User, CustomerProfile, SecurityAuditLog
from ..security.auth import permission_required
from ..views.auth_views import get_client_ip
from django.conf import settings
from ..security.crypto import sign_transaction, verify_signature
import json
from django.utils import timezone
import uuid
from decimal import Decimal, InvalidOperation


@login_required
@permission_required('view_customer_data')
def teller_dashboard(request):
    """Teller dashboard view"""
    pending_transactions = Transaction.objects.filter(
        status='pending'
    ).order_by('-timestamp')[:10]

    customers_without_account = User.objects.filter(
        user_type='customer',
        account__isnull=True
    )

    context = {
        'customers_without_account': customers_without_account,
        'pending_transactions': pending_transactions,
    }

    return render(request, 'dashboard/teller.html', context)


@login_required
@permission_required('view_customer_data')
def search_customer(request):
    """Search for customer by account number or name"""
    query = request.GET.get('query', '')
    customers = []

    if query:
        customer_profiles = CustomerProfile.objects.filter(
            account_number__icontains=query)
        users = User.objects.filter(
            username__icontains=query, user_type='customer')

        customer_ids = set()
        for profile in customer_profiles:
            customer_ids.add(profile.user.id)
        for user in users:
            customer_ids.add(user.id)

        customers = User.objects.filter(id__in=customer_ids)

    return render(request, 'teller/search_customer.html', {
        'customers': customers,
        'query': query
    })


@login_required
@permission_required('view_customer_data')
def customer_detail(request, customer_id):
    """View customer details"""
    customer = get_object_or_404(User, id=customer_id, user_type='customer')

    try:
        profile = CustomerProfile.objects.get(user=customer)
    except CustomerProfile.DoesNotExist:
        profile = None

    accounts = Account.objects.filter(customer=customer)

    # Log access to sensitive customer data
    from ..models import SecurityAuditLog
    SecurityAuditLog.objects.create(
        user=request.user,
        event_type='sensitive_access',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        description=f"Teller accessed customer data: {customer.username}",
        additional_data={
            "access_type": "customer_details",
            "customer_id": customer.id,
            "customer_username": customer.username,
            "teller_username": request.user.username,
            "access_time": timezone.now().isoformat(),
            "has_profile": profile is not None,
            "account_count": accounts.count() if accounts else 0
        }
    )

    context = {
        'customer': customer,
        'profile': profile,
        'accounts': accounts,
        'is_active': customer.is_active
    }

    return render(request, 'teller/customer_detail.html', context)


@login_required
@permission_required('process_transaction')
def process_transaction(request, transaction_id):
    """Process a pending transaction with digital signature verification"""
    transaction = get_object_or_404(
        Transaction, transaction_id=transaction_id, status='pending')

    if request.method == 'POST':
        action = request.POST.get('action')
        # Only approve triggers verification
        if action == 'approve':
            # Verify inbound digital signature
            if transaction.digital_signature:
                data = {
                    'id': str(transaction.transaction_id),
                    'account': transaction.account.account_number,
                    'amount': str(Decimal(transaction.amount)),
                    'recipient': transaction.recipient_account,
                    'timestamp': transaction.timestamp.isoformat()
                }
                if not verify_signature(data, transaction.digital_signature):
                    transaction.status = 'failed'
                    transaction.save()
                    messages.error(
                        request, "Transaksi gagal: Tanda tangan digital tidak valid.")
                    return redirect('teller_dashboard')

            # Perform transfer logic
            source_account = transaction.account
            try:
                dest_account = Account.objects.get(
                    account_number=transaction.recipient_account)
                if source_account.balance >= transaction.amount:
                    source_account.balance -= transaction.amount
                    dest_account.balance += transaction.amount
                    source_account.save()
                    dest_account.save()
                    transaction.status = 'completed'
                else:
                    transaction.status = 'failed'
                    messages.error(
                        request, "Transaksi gagal: Saldo tidak mencukupi.")
            except Account.DoesNotExist:
                transaction.status = 'failed'
                messages.error(
                    request, "Transaksi gagal: Rekening tujuan tidak ditemukan.")

            transaction.processed_by = request.user
            # Sign outbound approval event
            out_data = {
                'id': str(transaction.transaction_id),
                'account': source_account.account_number,
                'amount': str(transaction.amount),
                'recipient': transaction.recipient_account,
                'timestamp': transaction.timestamp.isoformat()
            }
            transaction.digital_signature = sign_transaction(out_data)
            transaction.save()
            # Log transaction processing
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='transaction',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"Processed transaction {transaction_id}: {action}",
                additional_data={
                    'new_status': transaction.status,
                    'digital_signature': bool(transaction.digital_signature),
                }
            )
            if transaction.status == 'completed':
                messages.success(request, "Transaksi berhasil diproses.")

        elif action == 'reject':
            transaction.status = 'cancelled'
            transaction.processed_by = request.user
            transaction.save()
            messages.success(request, "Transaksi dibatalkan.")
            # Log transaction rejection
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='transaction',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"Rejected transaction {transaction_id}",
                additional_data={'action': 'reject'}
            )
        return redirect('teller_dashboard')

    return render(request, 'teller/process_transaction.html', {'transaction': transaction})


@login_required
@permission_required('process_transaction')
def create_account(request, customer_id):
    """Create new account for existing customer by teller"""
    customer = get_object_or_404(User, id=customer_id, user_type='customer')

    if Account.objects.filter(customer=customer).exists():
        messages.error(
            request,
            f"Nasabah {customer.username} sudah memiliki rekening. Tidak dapat membuat rekening lagi."
        )
        return redirect('customer_detail', customer_id=customer_id)

    try:
        profile = CustomerProfile.objects.get(user=customer)
    except CustomerProfile.DoesNotExist:
        messages.error(
            request, "Nasabah belum memiliki profil. Harap lengkapi profil terlebih dahulu.")
        return redirect('customer_detail', customer_id=customer_id)

    if request.method == 'POST':
        account_number = f"ACC-{uuid.uuid4().hex[:8].upper()}"
        initial_balance = request.POST.get('initial_balance', '0')

        try:
            initial_balance = Decimal(initial_balance.replace(',', '.'))

            account = Account.objects.create(
                account_number=account_number,
                customer=customer,
                balance=initial_balance,
                is_active=True,
                created_at=timezone.now()
            )

            # Log account creation
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='transaction',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"Teller {request.user.username} membuat rekening baru untuk nasabah {customer.username}",
                additional_data={
                    "account_number": account_number,
                    "customer_id": customer.id,
                    "customer_username": customer.username,
                    "initial_balance": str(initial_balance),
                    "created_at": timezone.now().isoformat(),
                    "created_by": request.user.username
                }
            )

            # If initial deposit, create a transaction record
            if initial_balance > 0:
                Transaction.objects.create(
                    account=account,
                    transaction_type='deposit',
                    amount=initial_balance,
                    timestamp=timezone.now(),
                    description="Setoran awal pembukaan rekening",
                    status='completed',
                    processed_by=request.user
                )

            messages.success(
                request, f"Rekening baru berhasil dibuat dengan nomor {account_number}")
            return redirect('customer_detail', customer_id=customer_id)

        except (ValueError, InvalidOperation):
            messages.error(request, "Nilai setoran awal tidak valid.")
            return render(request, 'teller/create_account.html', {'customer': customer})

    return render(request, 'teller/create_account.html', {'customer': customer})


@login_required
@permission_required('process_transaction')
def toggle_customer_status(request, customer_id):
    """Activate or deactivate a customer account"""
    customer = get_object_or_404(User, id=customer_id, user_type='customer')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action in ['activate', 'deactivate']:
            new_active_status = (action == 'activate')
            old_status = customer.is_active

            customer.is_active = new_active_status
            customer.save()

            # Update associated account status if exists
            accounts = Account.objects.filter(customer=customer)
            for account in accounts:
                account.is_active = new_active_status
                account.save()

            # Log the action
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type='security_update',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f"Teller {request.user.username} {'activated' if new_active_status else 'deactivated'} customer {customer.username}",
                additional_data={
                    "customer_id": customer.id,
                    "customer_username": customer.username,
                    "previous_status": "active" if old_status else "inactive",
                    "new_status": "active" if new_active_status else "inactive",
                    "affected_accounts": [a.account_number for a in accounts],
                    "action_time": timezone.now().isoformat()
                }
            )

            if new_active_status:
                messages.success(
                    request, f"Akun nasabah {customer.username} berhasil diaktifkan.")
            else:
                messages.success(
                    request, f"Akun nasabah {customer.username} berhasil dinonaktifkan.")

        else:
            messages.error(request, "Tindakan tidak valid.")

    return redirect('customer_detail', customer_id=customer_id)


@login_required
@permission_required('process_transaction')
def process_withdrawal(request):
    """Process a withdrawal transaction for a customer by teller"""
    if request.method == 'POST':
        account_number = request.POST.get('account_number')
        amount = request.POST.get('amount')
        description = request.POST.get('description', 'Penarikan via teller')

        try:
            amount = Decimal(amount.replace(',', '.'))
            if amount <= 0:
                messages.error(request, "Jumlah penarikan harus lebih dari 0.")
                return redirect('teller_dashboard')

            try:
                account = Account.objects.get(account_number=account_number)

                if not account.is_active:
                    messages.error(request, "Rekening tidak aktif.")
                    return redirect('customer_detail', customer_id=account.customer.id)

                if not account.customer.is_active:
                    messages.error(request, "Akun nasabah tidak aktif.")
                    return redirect('customer_detail', customer_id=account.customer.id)

                if account.balance < amount:
                    messages.error(request, "Saldo tidak mencukupi.")
                    return redirect('customer_detail', customer_id=account.customer.id)

                account.balance -= amount
                account.save()

                transaction = Transaction.objects.create(
                    account=account,
                    transaction_type='withdrawal',
                    amount=amount,
                    description=description,
                    status='completed',
                    processed_by=request.user
                )

                # Log the withdrawal
                SecurityAuditLog.objects.create(
                    user=request.user,
                    event_type='transaction',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    description=f"Teller {request.user.username} melakukan penarikan untuk nasabah {account.customer.username}",
                    additional_data={
                        "account_number": account_number,
                        "customer_id": account.customer.id,
                        "customer_username": account.customer.username,
                        "amount": str(amount),
                        "transaction_id": str(transaction.transaction_id),
                        "timestamp": timezone.now().isoformat()
                    }
                )

                messages.success(
                    request, f"Penarikan sebesar Rp {amount} berhasil diproses.")
                return redirect('customer_detail', customer_id=account.customer.id)

            except Account.DoesNotExist:
                messages.error(request, "Rekening tidak ditemukan.")
                return redirect('teller_dashboard')

        except (ValueError, InvalidOperation):
            messages.error(request, "Nilai penarikan tidak valid.")
            return redirect('teller_dashboard')

    # If not POST, redirect to teller dashboard
    return redirect('teller_dashboard')
