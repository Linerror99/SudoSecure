from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional
from ..core.database import get_db
from ..core.auth import get_current_active_user
from ..models.user import User
from ..schemas.credential import (
    CredentialCreate, CredentialUpdate, CredentialResponse,
    CredentialWithPassword, CredentialSearchResponse
)
from ..services.credential_service import CredentialService

router = APIRouter()


@router.post("/", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
async def create_credential(
    credential_data: CredentialCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Crée un nouvel identifiant chiffré"""
    credential_service = CredentialService(db)
    return credential_service.create_credential(current_user, credential_data)


@router.get("/", response_model=CredentialSearchResponse)
async def get_user_credentials(
    page: int = Query(1, ge=1, description="Numéro de page"),
    per_page: int = Query(20, ge=1, le=100, description="Nombre d'éléments par page"),
    search: Optional[str] = Query(None, description="Terme de recherche"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Récupère les identifiants de l'utilisateur avec recherche et pagination"""
    credential_service = CredentialService(db)
    
    if search:
        return credential_service.search_credentials(current_user, search, page, per_page)
    else:
        return credential_service.get_user_credentials(current_user, page, per_page)


@router.get("/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Récupère un identifiant par son ID (sans mot de passe déchiffré)"""
    credential_service = CredentialService(db)
    credential = credential_service.get_credential(current_user, credential_id)
    
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifiant non trouvé"
        )
    
    return credential


@router.post("/{credential_id}/reveal", response_model=CredentialWithPassword)
async def reveal_credential_password(
    credential_id: int,
    master_password_data: dict,  # {"master_password": "..."}
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Révèle le mot de passe déchiffré d'un identifiant"""
    credential_service = CredentialService(db)
    master_password = master_password_data.get("master_password")
    
    if not master_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mot de passe maître requis"
        )
    
    credential = credential_service.get_credential_with_password(
        current_user, credential_id, master_password
    )
    
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifiant non trouvé"
        )
    
    return credential


@router.put("/{credential_id}", response_model=CredentialResponse)
async def update_credential(
    credential_id: int,
    credential_update: CredentialUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Met à jour un identifiant"""
    credential_service = CredentialService(db)
    credential = credential_service.update_credential(
        current_user, credential_id, credential_update
    )
    
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifiant non trouvé"
        )
    
    return credential


@router.delete("/{credential_id}", response_model=dict)
async def delete_credential(
    credential_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Supprime un identifiant"""
    credential_service = CredentialService(db)
    
    if not credential_service.delete_credential(current_user, credential_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Identifiant non trouvé"
        )
    
    return {"message": "Identifiant supprimé avec succès"}