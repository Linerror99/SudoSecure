from datetime import datetime, timedelta
from typing import Optional
import pyotp
import qrcode
import io
import base64
import json
import secrets
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from ..models.user import User
from ..schemas.user import UserCreate, UserLogin, TokenResponse, Setup2FAResponse
from ..core.security import security_manager
from ..core.auth import create_access_token
from ..core.config import settings


class UserService:
    """Service pour la gestion des utilisateurs"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_user(self, user_create: UserCreate) -> User:
        """Crée un nouveau utilisateur"""
        # Vérifier si l'utilisateur existe déjà
        if self.db.query(User).filter(User.email == user_create.email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Un utilisateur avec cet email existe déjà"
            )
        
        if self.db.query(User).filter(User.username == user_create.username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Un utilisateur avec ce nom d'utilisateur existe déjà"
            )
        
        # Générer le sel pour le chiffrement
        encryption_salt = security_manager.generate_salt()
        
        # Hacher le mot de passe maître
        hashed_password = security_manager.hash_password(user_create.master_password)
        
        # Créer l'utilisateur
        user = User(
            email=user_create.email,
            username=user_create.username,
            hashed_master_password=hashed_password,
            encryption_salt=encryption_salt,
            is_verified=True  # Pour simplifier, on considère l'utilisateur comme vérifié
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        return user
    
    def authenticate_user(self, user_login: UserLogin) -> Optional[User]:
        """Authentifie un utilisateur"""
        user = self.db.query(User).filter(User.username == user_login.username).first()
        
        if not user:
            return None
        
        if not security_manager.verify_password(user_login.master_password, user.hashed_master_password):
            return None
        
        # Vérifier 2FA si activé
        if user.is_2fa_enabled:
            if not user_login.totp_code:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Code 2FA requis"
                )
            
            if not self.verify_totp(user, user_login.totp_code):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Code 2FA invalide"
                )
        
        # Mettre à jour la dernière connexion
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        return user
    
    def create_token_response(self, user: User) -> TokenResponse:
        """Crée une réponse de token pour un utilisateur authentifié"""
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": str(user.id)}, expires_delta=access_token_expires
        )
        
        from ..schemas.user import UserResponse
        user_response = UserResponse.from_orm(user)
        
        return TokenResponse(
            access_token=access_token,
            expires_in=settings.access_token_expire_minutes * 60,
            user=user_response
        )
    
    def setup_2fa(self, user: User) -> Setup2FAResponse:
        """Configure l'authentification à deux facteurs pour un utilisateur"""
        if user.is_2fa_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA déjà activé pour cet utilisateur"
            )
        
        # Générer un secret TOTP
        secret = pyotp.random_base32()
        
        # Générer des codes de récupération
        backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]
        
        # Chiffrer et stocker le secret et les codes de récupération
        if settings.encryption_key:
            # Utiliser la clé d'application pour chiffrer les secrets 2FA
            salt = b"sudosecure-2fa-salt-secret"
            encryption_key = security_manager.derive_key_from_password(settings.encryption_key, salt)
            
            # Chiffrer le secret TOTP
            user.totp_secret = security_manager.encrypt_password(secret, encryption_key)
            
            # Chiffrer les codes de récupération
            backup_codes_json = json.dumps(backup_codes)
            user.backup_codes = security_manager.encrypt_password(backup_codes_json, encryption_key)
        else:
            # Fallback : stockage moins sécurisé (comme avant)
            user.totp_secret = secret
            backup_codes_json = json.dumps(backup_codes)
            user.backup_codes = base64.b64encode(backup_codes_json.encode()).decode()
        
        self.db.commit()
        
        # Générer le QR code
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name=settings.app_name
        )
        
        # Créer le QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        qr_code_url = f"data:image/png;base64,{img_str}"
        
        return Setup2FAResponse(
            qr_code_url=qr_code_url,
            secret=secret,
            backup_codes=backup_codes
        )
    
    def verify_and_enable_2fa(self, user: User, totp_code: str) -> bool:
        """Vérifie le code TOTP et active la 2FA"""
        if not user.totp_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA non configuré"
            )
        
        if self.verify_totp(user, totp_code):
            user.is_2fa_enabled = True
            self.db.commit()
            return True
        
        return False
    
    def verify_totp(self, user: User, totp_code: str) -> bool:
        """Vérifie un code TOTP"""
        if not user.totp_secret:
            return False
        
        # Déchiffrer le secret TOTP si nécessaire
        secret = self._decrypt_totp_secret(user)
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(totp_code, valid_window=1)  # Fenêtre de tolérance
    
    def disable_2fa(self, user: User) -> bool:
        """Désactive la 2FA pour un utilisateur"""
        user.is_2fa_enabled = False
        user.totp_secret = None
        user.backup_codes = None
        self.db.commit()
        return True
    
    def get_user_encryption_key(self, user: User, master_password: str) -> bytes:
        """Dérive la clé de chiffrement à partir du mot de passe maître"""
        # Vérifier le mot de passe maître
        if not security_manager.verify_password(master_password, user.hashed_master_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Mot de passe maître incorrect"
            )
        
        # Dériver la clé de chiffrement
        encryption_key = security_manager.derive_key_from_password(
            master_password, user.encryption_salt
        )
        return encryption_key
    
    def _decrypt_totp_secret(self, user: User) -> str:
        """Déchiffre le secret TOTP stocké"""
        if not user.totp_secret:
            return None
        
        if settings.encryption_key:
            try:
                # Déchiffrer avec la clé d'application
                salt = b"sudosecure-2fa-salt-secret"
                encryption_key = security_manager.derive_key_from_password(settings.encryption_key, salt)
                return security_manager.decrypt_password(user.totp_secret, encryption_key)
            except Exception:
                # En cas d'échec, essayer comme secret non chiffré (migration)
                return user.totp_secret
        else:
            # Pas de chiffrement app, secret en clair
            return user.totp_secret