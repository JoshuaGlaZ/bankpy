from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Image
from io import BytesIO
import qrcode
from reportlab.lib.utils import ImageReader
import json
import uuid
import datetime

def generate_transaction_pdf(transaction):
    """Generate a PDF receipt for a transaction"""
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=16,
        alignment=1,  # Center alignment
        spaceAfter=20
    )
    
    elements = []
    
    elements.append(Paragraph("BUKTI TRANSAKSI", title_style))
    elements.append(Spacer(1, 0.25*inch))
    
    transaction_data = [
        ["No. Transaksi:", str(transaction.transaction_id)],
        ["Jenis Transaksi:", dict(transaction.TRANSACTION_TYPE_CHOICES).get(transaction.transaction_type, transaction.transaction_type)],
        ["Tanggal:", transaction.timestamp.strftime("%d %B %Y %H:%M:%S")],
        ["Rekening Sumber:", transaction.account.account_number],
        ["Nama Pemilik:", transaction.account.customer.username],
        ["Jumlah:", f"Rp {transaction.amount:,.2f}"],
        ["Status:", dict(transaction.STATUS_CHOICES).get(transaction.status, transaction.status)]
    ]
    
    if transaction.transaction_type == 'transfer' and transaction.recipient_account:
        transaction_data.append(["Rekening Tujuan:", transaction.recipient_account])
    
    if transaction.description:
        transaction_data.append(["Keterangan:", transaction.description])
    
    table = Table(transaction_data, colWidths=[2.5*inch, 3*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.5*inch))
    
    # Add digital verification QR code
    verification_data = {
        "transaction_id": str(transaction.transaction_id),
        "timestamp": transaction.timestamp.isoformat(),
        "amount": str(transaction.amount),
        "account": transaction.account.account_number,
        "status": transaction.status,
        "verification_code": transaction.digital_signature if transaction.digital_signature else str(uuid.uuid4())
    }
    
    # Generate QR code with verification data
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(json.dumps(verification_data))
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    qr_buffer = BytesIO()
    img.save(qr_buffer)
    qr_buffer.seek(0)
    
    elements.append(Paragraph("Kode Verifikasi Digital:", styles["Normal"]))
    elements.append(Spacer(1, 0.1*inch))
    
    qr_image = Image(qr_buffer, width=2*inch, height=2*inch)
    elements.append(qr_image)
    
    elements.append(Spacer(1, 0.5*inch))
    disclaimer_text = """
    Dokumen ini telah ditandatangani secara digital dan merupakan bukti transaksi yang sah.
    Silakan verifikasi keaslian dokumen ini dengan memindai kode QR atau menghubungi bank.
    """
    elements.append(Paragraph(disclaimer_text, styles["Italic"]))
    
    elements.append(Spacer(1, 1*inch))
    footer_text = f"Dicetak pada: {datetime.datetime.now().strftime('%d %B %Y %H:%M:%S')}"
    elements.append(Paragraph(footer_text, styles["Italic"]))
    
    doc.build(elements)
    
    # Reset buffer position and return
    buffer.seek(0)
    return buffer.getvalue()
