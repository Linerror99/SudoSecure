from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from fastapi import HTTPException, status
from ..models.credential import StoredCredential
from ..models.user import User
from ..schemas.credential import (
    CredentialCreate, CredentialUpdate, CredentialResponse, 
    CredentialWithPassword, CredentialSearchResponse
)
from ..core.security import security_manager
from ..core.config import settings
from .user_service import UserService


class CredentialService:
    """Service pour la gestion des identifiants stockés"""
    
    def __init__(self, db: Session):
        self.db = db
        self.user_service = UserService(db)
    
    def create_credential(self, user: User, credential_data: CredentialCreate) -> CredentialResponse:
        """Crée un nouvel identifiant chiffré"""
        # Obtenir la clé de chiffrement
        if settings.encryption_key:
            # Utiliser une clé d'application si définie
            salt = b"sudosecure-static-salt-cred"
            encryption_key = security_manager.derive_key_from_password(settings.encryption_key, salt)
        else:
            if not credential_data.master_password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Mot de passe requis pour chiffrer les données"
                )
            encryption_key = self.user_service.get_user_encryption_key(
                user, credential_data.master_password
            )
        
        # Chiffrer le mot de passe
        encrypted_password = security_manager.encrypt_password(
            credential_data.password, encryption_key
        )
        
        # Chiffrer les notes si présentes
        encrypted_notes = None
        if credential_data.notes:
            encrypted_notes = security_manager.encrypt_password(
                credential_data.notes, encryption_key
            )
        
        # Créer l'identifiant
        credential = StoredCredential(
            user_id=user.id,
            title=credential_data.title,
            website_url=credential_data.website_url,
            username=credential_data.username,
            encrypted_password=encrypted_password,
            encrypted_notes=encrypted_notes
        )
        
        self.db.add(credential)
        self.db.commit()
        self.db.refresh(credential)
        
        return CredentialResponse.from_orm(credential)
    
    def get_credential(self, user: User, credential_id: int) -> Optional[CredentialResponse]:
        """Récupère un identifiant par son ID"""
        credential = self.db.query(StoredCredential).filter(
            and_(
                StoredCredential.id == credential_id,
                StoredCredential.user_id == user.id
            )
        ).first()
        
        if not credential:
            return None
        
        # Mettre à jour la date du dernier accès
        credential.last_accessed = datetime.utcnow()
        self.db.commit()
        
        return CredentialResponse.from_orm(credential)
    
    def get_credential_with_password(
        self, user: User, credential_id: int, master_password: str
    ) -> Optional[CredentialWithPassword]:
        """Récupère un identifiant avec le mot de passe déchiffré"""
        credential = self.db.query(StoredCredential).filter(
            and_(
                StoredCredential.id == credential_id,
                StoredCredential.user_id == user.id
            )
        ).first()
        
        if not credential:
            return None
        
        # Obtenir la clé de chiffrement
        if settings.encryption_key:
            salt = b"sudosecure-static-salt-cred"
            encryption_key = security_manager.derive_key_from_password(settings.encryption_key, salt)
        else:
            encryption_key = self.user_service.get_user_encryption_key(user, master_password)
        
        try:
            # Déchiffrer le mot de passe
            decrypted_password = security_manager.decrypt_password(
                credential.encrypted_password, encryption_key
            )
            
            # Déchiffrer les notes si présentes
            decrypted_notes = None
            if credential.encrypted_notes:
                decrypted_notes = security_manager.decrypt_password(
                    credential.encrypted_notes, encryption_key
                )
            
            # Mettre à jour la date du dernier accès
            credential.last_accessed = datetime.utcnow()
            self.db.commit()
            
            # Créer la réponse avec mot de passe déchiffré
            credential_dict = {
                "id": credential.id,
                "title": credential.title,
                "website_url": credential.website_url,
                "username": credential.username,
                "notes": decrypted_notes,
                "password": decrypted_password,
                "created_at": credential.created_at,
                "updated_at": credential.updated_at,
                "last_accessed": credential.last_accessed
            }
            
            return CredentialWithPassword(**credential_dict)
            
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Impossible de déchiffrer les données"
            )
    
    def update_credential(
        self, user: User, credential_id: int, credential_update: CredentialUpdate
    ) -> Optional[CredentialResponse]:
        """Met à jour un identifiant"""
        credential = self.db.query(StoredCredential).filter(
            and_(
                StoredCredential.id == credential_id,
                StoredCredential.user_id == user.id
            )
        ).first()
        
        if not credential:
            return None
        
        # Obtenir la clé de chiffrement uniquement si nécessaire (si champs chiffrés changent)
        needs_encryption = (credential_update.password is not None) or (credential_update.notes is not None)
        encryption_key = None
        if needs_encryption:
            if settings.encryption_key:
                salt = b"sudosecure-static-salt-cred"
                encryption_key = security_manager.derive_key_from_password(settings.encryption_key, salt)
            else:
                if not credential_update.master_password:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Mot de passe requis pour mettre à jour les données chiffrées"
                    )
                encryption_key = self.user_service.get_user_encryption_key(
                    user, credential_update.master_password
                )
        
        # Mettre à jour les champs non chiffrés
        if credential_update.title is not None:
            credential.title = credential_update.title
        if credential_update.website_url is not None:
            credential.website_url = credential_update.website_url
        if credential_update.username is not None:
            credential.username = credential_update.username
        
        # Mettre à jour le mot de passe chiffré si fourni
        if credential_update.password is not None:
            credential.encrypted_password = security_manager.encrypt_password(
                credential_update.password, encryption_key
            )
        
        # Mettre à jour les notes chiffrées si fournies
        if credential_update.notes is not None:
            if credential_update.notes:
                credential.encrypted_notes = security_manager.encrypt_password(
                    credential_update.notes, encryption_key
                )
            else:
                credential.encrypted_notes = None
        
        credential.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(credential)
        
        return CredentialResponse.from_orm(credential)
    
    def delete_credential(self, user: User, credential_id: int) -> bool:
        """Supprime un identifiant"""
        credential = self.db.query(StoredCredential).filter(
            and_(
                StoredCredential.id == credential_id,
                StoredCredential.user_id == user.id
            )
        ).first()
        
        if not credential:
            return False
        
        self.db.delete(credential)
        self.db.commit()
        return True
    
    def search_credentials(
        self, user: User, query: str, page: int = 1, per_page: int = 20
    ) -> CredentialSearchResponse:
        """Recherche des identifiants par titre ou nom d'utilisateur"""
        offset = (page - 1) * per_page
        
        # Recherche insensible à la casse
        search_filter = or_(
            StoredCredential.title.ilike(f"%{query}%"),
            StoredCredential.username.ilike(f"%{query}%"),
            StoredCredential.website_url.ilike(f"%{query}%")
        )
        
        # Compter le total
        total = self.db.query(StoredCredential).filter(
            and_(
                StoredCredential.user_id == user.id,
                search_filter
            )
        ).count()
        
        # Récupérer les résultats paginés
        credentials = self.db.query(StoredCredential).filter(
            and_(
                StoredCredential.user_id == user.id,
                search_filter
            )
        ).order_by(StoredCredential.title).offset(offset).limit(per_page).all()
        
        results = [CredentialResponse.from_orm(cred) for cred in credentials]
        
        return CredentialSearchResponse(
            results=results,
            total=total,
            page=page,
            per_page=per_page
        )
    
    def get_user_credentials(
        self, user: User, page: int = 1, per_page: int = 20
    ) -> CredentialSearchResponse:
        """Récupère tous les identifiants d'un utilisateur avec pagination"""
        offset = (page - 1) * per_page
        
        # Compter le total
        total = self.db.query(StoredCredential).filter(
            StoredCredential.user_id == user.id
        ).count()
        
        # Récupérer les résultats paginés
        credentials = self.db.query(StoredCredential).filter(
            StoredCredential.user_id == user.id
        ).order_by(StoredCredential.title).offset(offset).limit(per_page).all()
        
        results = [CredentialResponse.from_orm(cred) for cred in credentials]
        
        return CredentialSearchResponse(
            results=results,
            total=total,
            page=page,
            per_page=per_page
        )