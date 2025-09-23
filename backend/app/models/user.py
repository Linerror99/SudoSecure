from sqlalchemy import Column, Integer, String, Boolean, DateTime, LargeBinary, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from ..core.database import Base


class User(Base):
    """Modèle utilisateur avec support 2FA"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    
    # Mot de passe maître haché avec Argon2
    hashed_master_password = Column(String(255), nullable=False)
    
    # Sel unique pour la dérivation de clé de chiffrement
    encryption_salt = Column(LargeBinary, nullable=False)
    
    # Configuration 2FA
    is_2fa_enabled = Column(Boolean, default=False)
    totp_secret = Column(String(32), nullable=True)  # Secret TOTP pour 2FA
    backup_codes = Column(Text, nullable=True)  # Codes de récupération (chiffrés)
    
    # Métadonnées utilisateur
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relation avec les identifiants stockés
    credentials = relationship("StoredCredential", back_populates="owner", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email})>"