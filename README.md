## Fitur Utama
- Manajemen Pengguna & Peran: Nasabah, Teller, dan Manajer dengan hak akses berbeda
- Autentikasi Dua Faktor (2FA): TOTP compatible (Google Authenticator)
- Enkripsi Data Sensitif: Field terenkripsi untuk nomor KTP, alamat, dll
- Tanda Tangan Digital: RSA-PSS untuk integritas transaksi
- Kontrol Akses Berbasis Peran: RBAC untuk membatasi fungsi sesuai peran
- Audit Log Menyeluruh: Pencatatan aktivitas keamanan dan transaksi

## Screenshots
2FA Setup
<img width="1920" height="2020" alt="Screenshot 2025-07-13 at 23-13-56 Setup 2FA - Bank Py" src="https://github.com/user-attachments/assets/a495de84-feb2-4a84-ada6-4a7b451b013b" />

Audit Log
<img width="1920" height="1417" alt="Screenshot 2025-07-13 at 23-14-26 Log Audit Keamanan - Bank Py" src="https://github.com/user-attachments/assets/dc3048ef-1a55-4284-ab07-2ea8626638ab" />

## Installation
1. Clone repository:
```
git clone https://github.com/JoshuaGlaZ/bankpy.git
cd bankpy
```

2. Virtual enviroment:
```
python -m venv venv
source venv/bin/activate  # Linux/MacOS
venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

3. Run
```
python manage.py migrate
python manage.py createsuperuser
python manage.py createsuperuser
python manage.py seed_data # Simulasi Data
python manage.py runserver
```
