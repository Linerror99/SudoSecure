from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ..core.database import get_db
from ..core.auth import get_current_active_user
from ..models.user import User
from ..schemas.user import (
    UserCreate, UserLogin, UserResponse, TokenResponse,
    Setup2FAResponse, Verify2FARequest,
    PasswordGeneratorRequest, PasswordGeneratorResponse
)
from ..services.user_service import UserService
from ..core.security import security_manager

router = APIRouter()

# Rate limiting simple en mémoire pour /login
login_attempts = {}
LOCKOUT_DURATION = timedelta(minutes=15)
MAX_ATTEMPTS = 5


def get_client_ip(request: Request) -> str:
    """Récupère l'IP cliente en tenant compte des proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def is_rate_limited(ip: str) -> bool:
    """Vérifie si l'IP est limitée"""
    if ip not in login_attempts:
        return False
    
    attempts, last_attempt = login_attempts[ip]
    
    # Réinitialiser si le lockout est expiré
    if datetime.utcnow() - last_attempt > LOCKOUT_DURATION:
        del login_attempts[ip]
        return False
    
    return attempts >= MAX_ATTEMPTS


def record_failed_attempt(ip: str):
    """Enregistre une tentative échouée"""
    now = datetime.utcnow()
    if ip in login_attempts:
        attempts, _ = login_attempts[ip]
        login_attempts[ip] = (attempts + 1, now)
    else:
        login_attempts[ip] = (1, now)


def reset_attempts(ip: str):
    """Remet à zéro les tentatives après succès"""
    if ip in login_attempts:
        del login_attempts[ip]


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_create: UserCreate, db: Session = Depends(get_db)):
    """Inscription d'un nouveau utilisateur"""
    user_service = UserService(db)
    user = user_service.create_user(user_create)
    return UserResponse.from_orm(user)


@router.post("/login", response_model=TokenResponse)
async def login_user(
    user_login: UserLogin, 
    request: Request,
    db: Session = Depends(get_db)
):
    """Connexion d'un utilisateur avec rate limiting"""
    client_ip = get_client_ip(request)
    
    # Vérifier rate limiting
    if is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Trop de tentatives de connexion. Réessayez dans {LOCKOUT_DURATION.total_seconds()//60:.0f} minutes."
        )
    
    user_service = UserService(db)
    
    try:
        user = user_service.authenticate_user(user_login)
        
        if not user:
            record_failed_attempt(client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nom d'utilisateur ou mot de passe incorrect",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Succès : réinitialiser le compteur
        reset_attempts(client_ip)
        return user_service.create_token_response(user)
        
    except HTTPException as e:
        # Enregistrer l'échec si ce n'est pas déjà fait
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            record_failed_attempt(client_ip)
        raise


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Récupère les informations de l'utilisateur connecté"""
    return UserResponse.from_orm(current_user)


@router.post("/2fa/setup", response_model=Setup2FAResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Configure l'authentification à deux facteurs"""
    user_service = UserService(db)
    return user_service.setup_2fa(current_user)


@router.post("/2fa/verify", response_model=dict)
async def verify_2fa(
    verify_request: Verify2FARequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Vérifie et active l'authentification à deux facteurs"""
    user_service = UserService(db)
    
    if user_service.verify_and_enable_2fa(current_user, verify_request.totp_code):
        return {"message": "2FA activé avec succès"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code 2FA invalide"
        )


@router.delete("/2fa/disable", response_model=dict)
async def disable_2fa(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Désactive l'authentification à deux facteurs"""
    user_service = UserService(db)
    
    if user_service.disable_2fa(current_user):
        return {"message": "2FA désactivé avec succès"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Erreur lors de la désactivation de la 2FA"
        )


@router.post("/generate-password", response_model=PasswordGeneratorResponse)
async def generate_password(request: PasswordGeneratorRequest):
    """Génère un mot de passe sécurisé (pas besoin d'authentification)"""
    try:
        password = security_manager.generate_secure_password(
            length=request.length,
            include_uppercase=request.include_uppercase,
            include_lowercase=request.include_lowercase,
            include_numbers=request.include_numbers,
            include_symbols=request.include_symbols
        )
        
        # Calcul simple du score de force (0-100)
        strength_score = min(100, len(password) * 2 + 
                           (20 if request.include_uppercase else 0) +
                           (20 if request.include_lowercase else 0) +
                           (20 if request.include_numbers else 0) +
                           (20 if request.include_symbols else 0))
        
        return PasswordGeneratorResponse(
            password=password,
            length=len(password),
            strength_score=strength_score
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )