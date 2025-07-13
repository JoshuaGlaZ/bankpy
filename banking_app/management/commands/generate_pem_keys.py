from django.core.management.base import BaseCommand
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption
)
import os
import base64

class Command(BaseCommand):
    help = 'Generate RSA key pair in PEM format for transaction signing and save to .env file'

    def add_arguments(self, parser):
        parser.add_argument(
            '--env-file',
            default='.env',
            help='Path to the .env file to update (default: .env)'
        )
        parser.add_argument(
            '--key-size',
            type=int,
            default=2048,
            help='RSA key size in bits (default: 2048)'
        )

    def handle(self, *args, **options):
        env_file = options['env_file']
        key_size = options['key_size']
        
        self.stdout.write(self.style.WARNING(f'Generating new RSA key pair ({key_size} bits)...'))
        
        # Generate new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        public_key = private_key.public_key()
        
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create separate PEM files
        pem_dir = os.path.join(os.getcwd(), 'pem_keys')
        os.makedirs(pem_dir, exist_ok=True)
        
        private_key_path = os.path.join(pem_dir, 'transaction_signing_key.pem')
        public_key_path = os.path.join(pem_dir, 'transaction_verification_key.pem')
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
            
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        self.stdout.write(self.style.SUCCESS('RSA key pair generated successfully!'))
        self.stdout.write(f'Private key saved to: {private_key_path}')
        self.stdout.write(f'Public key saved to: {public_key_path}')
        self.stdout.write(self.style.WARNING('\nIMPORTANT: Keep your private key secure!'))