bankpy is a Django‑based banking information system that safeguards sensitive customer data with multi‑factor authentication, field‑level encryption, and cryptographic transaction signing. Built with robust role‑based access controls and comprehensive audit logging, it ensures both security and compliance for everyday banking operations.

- **User & Role Management** : Distinct access levels for Nasabah (Customer), Teller, and Manager
- **Two‑Factor Authentication (2FA)** : TOTP‑compatible setup via Google Authenticator
- **Field ** : AES‑encrypted storage of KTP numbers, addresses, and other PII
- **Digital Signatures** : RSA‑PSS to guarantee transaction integrity
- **Role‑Based Access Control** : Fine‑grained RBAC to enforce least‑privilege
- **Audit Logging** : Immutable logs of security events and transaction histories

## Screenshots
2FA Setup
<img width="1920" height="2020" alt="Screenshot 2025-07-13 at 23-13-56 Setup 2FA - Bank Py" src="https://github.com/user-attachments/assets/a495de84-feb2-4a84-ada6-4a7b451b013b" />

Audit Log
<img width="1920" height="1417" alt="Screenshot 2025-07-13 at 23-14-26 Log Audit Keamanan - Bank Py" src="https://github.com/user-attachments/assets/dc3048ef-1a55-4284-ab07-2ea8626638ab" />

## Installation
1. Clone repository:
```bash
git clone https://github.com/JoshuaGlaZ/bankpy.git
cd bankpy
```

2. Virtual enviroment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/MacOS
venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

3. Run
```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py seed_data # Simulate users data
python manage.py runserver
```
