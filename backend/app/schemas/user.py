from pydantic import BaseModel, EmailStr, validator
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    """Schéma de base pour un utilisateur"""
    email: EmailStr
    username: str
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores')
        if len(v) < 3:
            raise ValueError('Le nom d\'utilisateur doit contenir au moins 3 caractères')
        return v


class UserCreate(UserBase):
    """Schéma pour la création d'un utilisateur"""
    master_password: str
    
    @validator('master_password')
    def validate_password(cls, v):
        if len(v) < 12:
            raise ValueError('Le mot de passe maître doit contenir au moins 12 caractères')
        if not any(c.isupper() for c in v):
            raise ValueError('Le mot de passe maître doit contenir au moins une majuscule')
        if not any(c.islower() for c in v):
            raise ValueError('Le mot de passe maître doit contenir au moins une minuscule')
        if not any(c.isdigit() for c in v):
            raise ValueError('Le mot de passe maître doit contenir au moins un chiffre')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Le mot de passe maître doit contenir au moins un caractère spécial')
        return v


class UserLogin(BaseModel):
    """Schéma pour la connexion d'un utilisateur"""
    username: str
    master_password: str
    totp_code: Optional[str] = None  # Code 2FA optionnel


class UserResponse(UserBase):
    """Schéma de réponse pour un utilisateur"""
    id: int
    is_active: bool
    is_verified: bool
    is_2fa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Schéma de réponse pour l'authentification"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class Setup2FAResponse(BaseModel):
    """Schéma de réponse pour la configuration 2FA"""
    qr_code_url: str
    secret: str
    backup_codes: list[str]


class Verify2FARequest(BaseModel):
    """Schéma pour la vérification 2FA"""
    totp_code: str


class PasswordGeneratorRequest(BaseModel):
    """Schéma pour la génération de mot de passe"""
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_numbers: bool = True
    include_symbols: bool = True
    
    @validator('length')
    def validate_length(cls, v):
        if v < 4:
            raise ValueError('La longueur minimale est de 4 caractères')
        if v > 128:
            raise ValueError('La longueur maximale est de 128 caractères')
        return v


class PasswordGeneratorResponse(BaseModel):
    """Schéma de réponse pour la génération de mot de passe"""
    password: str
    length: int
    strength_score: int  # Score de force (0-100)