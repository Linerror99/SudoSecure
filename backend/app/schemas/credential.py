from pydantic import BaseModel, validator
from typing import Optional
from datetime import datetime


class CredentialBase(BaseModel):
    """Schéma de base pour un identifiant stocké"""
    title: str
    website_url: Optional[str] = None
    username: Optional[str] = None
    notes: Optional[str] = None
    
    @validator('title')
    def title_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Le titre ne peut pas être vide')
        if len(v.strip()) > 255:
            raise ValueError('Le titre ne peut pas dépasser 255 caractères')
        return v.strip()


class CredentialCreate(CredentialBase):
    """Schéma pour la création d'un identifiant"""
    password: str
    # Le mot de passe maître n'est plus requis pour la création
    master_password: Optional[str] = None
    
    @validator('password')
    def password_not_empty(cls, v):
        if not v:
            raise ValueError('Le mot de passe ne peut pas être vide')
        return v


class CredentialUpdate(BaseModel):
    """Schéma pour la mise à jour d'un identifiant"""
    title: Optional[str] = None
    website_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    notes: Optional[str] = None
    # Le mot de passe maître n'est plus requis pour la mise à jour
    master_password: Optional[str] = None


class CredentialResponse(CredentialBase):
    """Schéma de réponse pour un identifiant (sans mot de passe déchiffré)"""
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class CredentialWithPassword(CredentialResponse):
    """Schéma de réponse avec mot de passe déchiffré (pour affichage sécurisé)"""
    password: str


class CredentialSearchResponse(BaseModel):
    """Schéma de réponse pour la recherche d'identifiants"""
    results: list[CredentialResponse]
    total: int
    page: int
    per_page: int