import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import tempfile
import os

from app.main import app
from app.core.database import get_db, Base
from app.core.security import security_manager

# Configuration de la base de données de test
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_sudosecure.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Remplace la session de base de données pour les tests"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Configure la base de données de test"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    # Supprimer le fichier de base de données de test
    if os.path.exists("./test_sudosecure.db"):
        os.remove("./test_sudosecure.db")


@pytest.fixture
def client():
    """Client de test FastAPI"""
    return TestClient(app)


@pytest.fixture
def test_user_data():
    """Données d'utilisateur de test"""
    return {
        "email": "test@example.com",
        "username": "testuser",
        "master_password": "TestPassword123!@#"
    }


@pytest.fixture
def test_credential_data():
    """Données d'identifiant de test"""
    return {
        "title": "Test Service",
        "website_url": "https://example.com",
        "username": "testuser",
        "password": "TestPassword123",
        "notes": "Test notes",
        "master_password": "TestPassword123!@#"
    }


@pytest.fixture
def authenticated_client(client, test_user_data):
    """Client authentifié pour les tests"""
    # Créer un utilisateur
    response = client.post("/api/auth/register", json=test_user_data)
    assert response.status_code == 201
    
    # Se connecter
    login_data = {
        "username": test_user_data["username"],
        "master_password": test_user_data["master_password"]
    }
    response = client.post("/api/auth/login", json=login_data)
    assert response.status_code == 200
    
    token = response.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    
    return client