from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from ..models import Transaction, SecurityAuditLog, User
from ..security.auth import permission_required
from django.db.models import Sum, Count, Q
import csv
from datetime import datetime, timedelta, time
from django.utils import timezone
import calendar
from django.core.paginator import Paginator
import logging


@login_required
@permission_required('view_reports')
def manager_dashboard(request):
    """Manager dashboard view"""
    today = timezone.localtime().date()

    # Daily stats
    daily_transactions = Transaction.objects.filter(timestamp__date=today)
    daily_count = daily_transactions.count()
    daily_total = daily_transactions.aggregate(s=Sum('amount'))['s'] or 0

    # Monthly stats
    monthly_transactions = Transaction.objects.filter(
        timestamp__year=today.year,
        timestamp__month=today.month,
    )
    monthly_count = monthly_transactions.count()
    monthly_total = monthly_transactions.aggregate(s=Sum('amount'))['s'] or 0

    # Get pending transactions
    pending_transactions = Transaction.objects.filter(
        status='pending'
    ).order_by('-timestamp')[:5]

    # Get recent audit logs
    recent_logs = SecurityAuditLog.objects.all().order_by('-timestamp')[:10]

    context = {
        'daily_count': daily_count,
        'daily_total': daily_total,
        'monthly_count': monthly_count,
        'monthly_total': monthly_total,
        'pending_transactions': pending_transactions,
        'recent_logs': recent_logs,
    }

    return render(request, 'dashboard/manager.html', context)


@login_required
@permission_required('view_audit_logs')
def audit_log_view(request):
    """View security audit logs"""
    # Get filter parameters
    event_type = request.GET.get('event_type', '')
    username = request.GET.get('username', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')

    logs = SecurityAuditLog.objects.all()

    if event_type:
        logs = logs.filter(event_type=event_type)

    if username:
        logs = logs.filter(user__username__icontains=username)

    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        start_datetime = timezone.make_aware(
            datetime.combine(start_date, time.min))
        logs = logs.filter(timestamp__gte=start_datetime)

    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        end_datetime = timezone.make_aware(
            datetime.combine(end_date, time.max))
        logs = logs.filter(timestamp__lte=end_datetime)

    logs = logs.order_by('-timestamp')

    paginator = Paginator(logs, 10)
    page_number = request.GET.get('page', 1)
    logs_page = paginator.get_page(page_number)
    event_types = SecurityAuditLog.objects.values_list(
        'event_type', flat=True).distinct()

    context = {
        'logs': logs_page,
        'event_types': event_types,
        'filters': {
            'event_type': event_type,
            'username': username,
            'start_date': start_date,
            'end_date': end_date
        }
    }

    return render(request, 'manager/audit_logs.html', context)


@login_required
@permission_required('view_audit_logs')
def audit_log_detail(request):
    """API to get security audit log detail as JSON"""
    log_id = request.GET.get('log_id')
    if not log_id:
        return JsonResponse({'error': 'Missing log_id parameter'}, status=400)

    try:
        log = SecurityAuditLog.objects.get(id=log_id)

        response_data = {
            'id': log.id,
            'timestamp': log.timestamp.strftime('%d %b %Y %H:%M:%S'),
            'event_type': log.event_type,
            'user': log.user.username if log.user else 'Anonymous',
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'description': log.description,
            'additional_data': log.additional_data
        }

        return JsonResponse(response_data)
    except SecurityAuditLog.DoesNotExist:
        return JsonResponse({'error': 'Log not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@permission_required('view_reports')
def export_transaction_report(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="transactions_report.csv"'

    sd = request.GET.get('start_date')
    ed = request.GET.get('end_date')
    today = timezone.localdate()
    start_date = datetime.strptime(
        sd, '%Y-%m-%d').date() if sd else today - timedelta(days=30)
    end_date = datetime.strptime(ed, '%Y-%m-%d').date() if ed else today

    start_dt = timezone.make_aware(datetime.combine(start_date, time.min))
    end_dt = timezone.make_aware(datetime.combine(end_date,   time.max))

    qs = Transaction.objects.filter(
        timestamp__range=(start_dt, end_dt)
    ).order_by('-timestamp')

    # Debug log
    logger = logging.getLogger(__name__)
    logger.debug(
        f"Exporting {qs.count()} transaksi dari {start_date} sampai {end_date}")

    writer = csv.writer(response)
    writer.writerow(['Transaction ID', 'Account', 'Type',
                    'Amount', 'Status', 'Timestamp', 'Processed By'])

    for tx in qs:
        writer.writerow([
            tx.transaction_id,
            tx.account.account_number,
            tx.transaction_type,
            tx.amount,
            tx.status,
            tx.timestamp.isoformat(),
            tx.processed_by.username if tx.processed_by else 'N/A',
        ])
        
    # Log export as sensitive access
    SecurityAuditLog.objects.create(
        user=request.user,
        event_type='sensitive_access',
        ip_address=request.META.get('REMOTE_ADDR', '0.0.0.0'),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        description=f"Exported {qs.count()} transactions as CSV",
        additional_data={
            'export_type': 'transaction_report',
            'filter_criteria': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        }
    )

    return response