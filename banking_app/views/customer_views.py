from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, HttpResponse
from django.contrib import messages
from django.db.models import Sum, Q
from ..models import Account, Transaction, User
from ..security.auth import permission_required
from ..utils.pdf_generator import generate_transaction_pdf
import json
from decimal import Decimal, ROUND_DOWN
from django.core.paginator import Paginator


@login_required
@permission_required('view_own_data')
def customer_dashboard(request):
    """Customer dashboard view"""
    user = request.user

    accounts = Account.objects.filter(customer=user)
    total_balance = accounts.aggregate(total=Sum('balance'))['total'] or 0

    # Get all user account numbers for finding incoming transactions
    user_account_numbers = list(
        accounts.values_list('account_number', flat=True))

    # Get both outgoing and incoming transactions - only the 5 most recent
    recent_transactions = Transaction.objects.filter(
        # Transactions where user's account is the source
        Q(account__in=accounts) |
        # Transactions where user's account is the recipient
        Q(recipient_account__in=user_account_numbers)
    ).order_by('-timestamp')[:5]  # Get only 5 most recent transactions

    context = {
        'accounts': accounts,
        'total_balance': total_balance,
        'recent_transactions': recent_transactions,
        'user_account_numbers': user_account_numbers,
    }

    return render(request, 'dashboard/customer.html', context)


@login_required
@permission_required('view_own_data')
def transaction_history(request):
    """View transaction history for customer"""
    user = request.user

    accounts = Account.objects.filter(customer=user)
    user_account_numbers = list(
        accounts.values_list('account_number', flat=True))

    account_id = request.GET.get('account_id')
    transaction_type = request.GET.get('transaction_type')
    status = request.GET.get('status')

    # Start with a base query
    transactions_query = Transaction.objects

    if account_id:
        # Filter transactions for specific account (both outgoing and incoming)
        account = get_object_or_404(Account, id=account_id, customer=user)
        transactions_query = transactions_query.filter(
            Q(account=account) |  # Outgoing transactions
            Q(recipient_account=account.account_number)  # Incoming transactions
        )
    else:
        # Get all transactions for all accounts (both outgoing and incoming)
        transactions_query = transactions_query.filter(
            Q(account__in=accounts) |  # Outgoing transactions
            Q(recipient_account__in=user_account_numbers)  # Incoming transactions
        )

    if transaction_type:
        transactions_query = transactions_query.filter(
            transaction_type=transaction_type)

    if status:
        transactions_query = transactions_query.filter(status=status)

    transactions_query = transactions_query.order_by('-timestamp')

    # Show 10 transactions per page
    paginator = Paginator(transactions_query, 10)
    page_number = request.GET.get('page', 1)
    transactions = paginator.get_page(page_number)

    context = {
        'transactions': transactions,
        'accounts': accounts,
        'selected_account_id': account_id,
        'selected_transaction_type': transaction_type,
        'selected_status': status,
        'user_account_numbers': user_account_numbers,
    }

    return render(request, 'transaction/history.html', context)


@login_required
@permission_required('make_transaction')
def new_transfer(request):
    """Create a new transfer transaction"""
    user = request.user
    accounts = Account.objects.filter(customer=user)

    if request.method == 'POST':
        from_account_id = request.POST.get('from_account')
        to_account_number = request.POST.get('to_account')
        amount = request.POST.get('amount')
        description = request.POST.get('description', '')

        try:
            from_account = get_object_or_404(
                Account, id=from_account_id, customer=user)
            amount_decimal = Decimal(amount)
            amount_decimal = amount_decimal.quantize(Decimal('0.00'), rounding=ROUND_DOWN)

            if amount_decimal <= 0:
                messages.error(request, "Jumlah transfer harus lebih dari 0.")
                return render(request, 'transaction/new_transfer.html', {'accounts': accounts})

            if from_account.balance < amount_decimal:
                messages.error(request, "Saldo tidak mencukupi.")
                return render(request, 'transaction/new_transfer.html', {'accounts': accounts})

            transaction = Transaction.objects.create(
                account=from_account,
                transaction_type='transfer',
                amount=amount_decimal,
                description=description,
                status='pending',
                recipient_account=to_account_number
            )

            # Add digital signature
            from ..security.crypto import sign_transaction
            from django.conf import settings

            transaction_data = {
                'id': str(transaction.transaction_id),
                'account': from_account.account_number,
                'amount': str(amount_decimal),
                'recipient': to_account_number,
                'timestamp': transaction.timestamp.isoformat()
            }

            signature = sign_transaction(transaction_data)
            transaction.digital_signature = signature
            transaction.save()

            messages.success(
                request, "Transfer berhasil dibuat dan sedang diproses.")
            return redirect('transaction_history')

        except (ValueError, TypeError):
            messages.error(request, "Data transfer tidak valid.")

    return render(request, 'transaction/new_transfer.html', {'accounts': accounts})


@login_required
@permission_required('view_own_data')
def download_transaction_pdf(request, transaction_id):
    """Download transaction receipt as PDF"""
    user = request.user
    accounts = Account.objects.filter(customer=user)
    try:
        transaction = Transaction.objects.get(
            transaction_id=transaction_id,
            account__in=accounts
        )
    except Transaction.DoesNotExist:
        # Render 404
        return render(
            request,
            'transaction/404_transaction.html',
            {
                'message': 'Transaksi tidak ditemukan atau Anda tidak memiliki izin untuk mengakses dokumen ini.'
            },
            status=404
        )

    # Generate PDF
    pdf_data = generate_transaction_pdf(transaction)
    response = HttpResponse(pdf_data, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="transaction_{transaction_id}.pdf"'
    return response
