from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
from .core.config import settings
from .core.database import engine
from .models import Base
from .api.auth import router as auth_router
from .api.credentials import router as credentials_router

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestionnaire de cycle de vie de l'application"""
    # Startup
    logger.info("Démarrage de l'application SudoSecure")
    
    # Créer les tables de base de données
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Tables de base de données créées avec succès")
    except Exception as e:
        logger.error(f"Erreur lors de la création des tables: {e}")
    
    yield
    
    # Shutdown
    logger.info("Arrêt de l'application SudoSecure")


# Création de l'application FastAPI
app = FastAPI(
    title="SudoSecure API",
    description="API sécurisée pour la gestion de mots de passe",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


# Gestionnaire d'erreurs global
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Gestionnaire d'erreurs global pour éviter les fuites d'information"""
    logger.error(f"Erreur non gérée: {exc}")
    
    if settings.debug:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Erreur interne: {str(exc)}"}
        )
    else:
        return JSONResponse(
            status_code=500,
            content={"detail": "Erreur interne du serveur"}
        )


# Routes de base
@app.get("/")
async def root():
    """Point d'entrée de l'API"""
    return {
        "message": "SudoSecure API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Vérification de l'état de l'API"""
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}


# Inclusion des routeurs
app.include_router(
    auth_router,
    prefix="/api/auth",
    tags=["Authentification"]
)

app.include_router(
    credentials_router,
    prefix="/api/credentials",
    tags=["Identifiants"]
)

# Point d'entrée pour le développement
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug
    )