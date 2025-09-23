from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.context import CryptContext
import base64
import os
from typing import Union
import secrets

# Configuration du contexte de hachage avec Argon2
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


class SecurityManager:
    """Gestionnaire de sécurité pour le chiffrement et hachage"""
    
    def __init__(self):
        self.pwd_context = pwd_context
    
    def hash_password(self, password: str) -> str:
        """Hache un mot de passe avec Argon2"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Vérifie un mot de passe contre son hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Dérive une clé de chiffrement à partir d'un mot de passe maître"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Nombre d'itérations pour PBKDF2
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def generate_salt(self) -> bytes:
        """Génère un sel aléatoire"""
        return os.urandom(16)
    
    def encrypt_password(self, password: str, encryption_key: bytes) -> str:
        """Chiffre un mot de passe avec AES-256"""
        fernet = Fernet(encryption_key)
        encrypted_password = fernet.encrypt(password.encode())
        return base64.urlsafe_b64encode(encrypted_password).decode()
    
    def decrypt_password(self, encrypted_password: str, encryption_key: bytes) -> str:
        """Déchiffre un mot de passe"""
        try:
            fernet = Fernet(encryption_key)
            encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
            decrypted_password = fernet.decrypt(encrypted_data)
            return decrypted_password.decode()
        except Exception:
            raise ValueError("Impossible de déchiffrer le mot de passe")
    
    def generate_secure_password(
        self, 
        length: int = 16, 
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_numbers: bool = True,
        include_symbols: bool = True
    ) -> str:
        """Génère un mot de passe sécurisé"""
        characters = ""
        
        if include_lowercase:
            characters += "abcdefghijklmnopqrstuvwxyz"
        if include_uppercase:
            characters += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if include_numbers:
            characters += "0123456789"
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            raise ValueError("Au moins un type de caractère doit être inclus")
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password


# Instance globale du gestionnaire de sécurité
security_manager = SecurityManager()