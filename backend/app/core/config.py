from pydantic_settings import BaseSettings
from typing import Optional, List, Union
from pydantic import field_validator, Field
import secrets


class Settings(BaseSettings):
    """Configuration de l'application avec gestion sécurisée des variables d'environnement"""
    
    # Base de données
    database_url: str = "postgresql://sudosecure:sudosecure@localhost:5432/sudosecure_db"
    
    # JWT Configuration
    secret_key: str = secrets.token_urlsafe(32)  # Généré automatiquement si non fourni
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # CORS Configuration
    allowed_origins: Union[List[str], str] = Field(
        default=["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:8080"]
    )
    
    # Sécurité
    # Clé pour le chiffrement AES des mots de passe stockés (doit être définie en production)
    encryption_key: Optional[str] = None
    
    # Configuration 2FA
    app_name: str = "SudoSecure"
    
    # Configuration de l'environnement
    environment: str = "development"
    debug: bool = True
    
    @field_validator('allowed_origins', mode='before')
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from string or list"""
        if isinstance(v, str):
            # Si c'est une chaîne, la séparer par des virgules
            return [origin.strip() for origin in v.split(',') if origin.strip()]
        return v
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8"
    }

# Instance globale des paramètres
settings = Settings()