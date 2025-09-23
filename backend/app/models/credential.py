from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from ..core.database import Base


class StoredCredential(Base):
    """Modèle pour les identifiants stockés (mots de passe chiffrés)"""
    __tablename__ = "stored_credentials"

    id = Column(Integer, primary_key=True, index=True)
    
    # Référence vers l'utilisateur propriétaire
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Informations de l'identifiant
    title = Column(String(255), nullable=False, index=True)  # Nom/titre du service
    website_url = Column(String(500), nullable=True)  # URL du site web
    username = Column(String(255), nullable=True, index=True)  # Nom d'utilisateur/email
    
    # Mot de passe chiffré avec AES-256
    encrypted_password = Column(Text, nullable=False)
    
    # Notes optionnelles (chiffrées)
    encrypted_notes = Column(Text, nullable=True)
    
    # Métadonnées
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_accessed = Column(DateTime(timezone=True), nullable=True)
    
    # Relation avec l'utilisateur
    owner = relationship("User", back_populates="credentials")

    def __repr__(self):
        return f"<StoredCredential(id={self.id}, title={self.title}, user_id={self.user_id})>"