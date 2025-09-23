import pytest
from fastapi.testclient import TestClient


class TestUserRegistration:
    """Tests pour l'inscription d'utilisateur"""
    
    def test_register_valid_user(self, client, test_user_data):
        """Test d'inscription avec des données valides"""
        response = client.post("/api/auth/register", json=test_user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == test_user_data["email"]
        assert data["username"] == test_user_data["username"]
        assert data["is_active"] is True
        assert data["is_verified"] is True
        assert data["is_2fa_enabled"] is False
        assert "id" in data
        assert "created_at" in data
    
    def test_register_duplicate_email(self, client, test_user_data):
        """Test d'inscription avec un email déjà utilisé"""
        # Première inscription
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 201
        
        # Deuxième inscription avec le même email
        duplicate_data = test_user_data.copy()
        duplicate_data["username"] = "differentuser"
        response = client.post("/api/auth/register", json=duplicate_data)
        
        assert response.status_code == 400
        assert "email existe déjà" in response.json()["detail"]
    
    def test_register_duplicate_username(self, client, test_user_data):
        """Test d'inscription avec un nom d'utilisateur déjà utilisé"""
        # Première inscription
        response = client.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 201
        
        # Deuxième inscription avec le même nom d'utilisateur
        duplicate_data = test_user_data.copy()
        duplicate_data["email"] = "different@example.com"
        response = client.post("/api/auth/register", json=duplicate_data)
        
        assert response.status_code == 400
        assert "nom d'utilisateur existe déjà" in response.json()["detail"]
    
    def test_register_invalid_email(self, client, test_user_data):
        """Test d'inscription avec un email invalide"""
        invalid_data = test_user_data.copy()
        invalid_data["email"] = "invalid-email"
        
        response = client.post("/api/auth/register", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    def test_register_weak_password(self, client, test_user_data):
        """Test d'inscription avec un mot de passe faible"""
        weak_data = test_user_data.copy()
        weak_data["master_password"] = "weak"
        
        response = client.post("/api/auth/register", json=weak_data)
        assert response.status_code == 422  # Validation error
    
    def test_register_short_username(self, client, test_user_data):
        """Test d'inscription avec un nom d'utilisateur trop court"""
        short_data = test_user_data.copy()
        short_data["username"] = "ab"
        
        response = client.post("/api/auth/register", json=short_data)
        assert response.status_code == 422  # Validation error


class TestUserLogin:
    """Tests pour la connexion d'utilisateur"""
    
    def test_login_valid_credentials(self, client, test_user_data):
        """Test de connexion avec des identifiants valides"""
        # D'abord s'inscrire
        client.post("/api/auth/register", json=test_user_data)
        
        # Puis se connecter
        login_data = {
            "username": test_user_data["username"],
            "master_password": test_user_data["master_password"]
        }
        response = client.post("/api/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert "user" in data
        assert data["user"]["username"] == test_user_data["username"]
    
    def test_login_invalid_username(self, client, test_user_data):
        """Test de connexion avec un nom d'utilisateur invalide"""
        # D'abord s'inscrire
        client.post("/api/auth/register", json=test_user_data)
        
        # Tentative de connexion avec un mauvais nom d'utilisateur
        login_data = {
            "username": "wronguser",
            "master_password": test_user_data["master_password"]
        }
        response = client.post("/api/auth/login", json=login_data)
        
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"]
    
    def test_login_invalid_password(self, client, test_user_data):
        """Test de connexion avec un mot de passe invalide"""
        # D'abord s'inscrire
        client.post("/api/auth/register", json=test_user_data)
        
        # Tentative de connexion avec un mauvais mot de passe
        login_data = {
            "username": test_user_data["username"],
            "master_password": "WrongPassword123!"
        }
        response = client.post("/api/auth/login", json=login_data)
        
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"]


class TestUserInfo:
    """Tests pour la récupération des informations utilisateur"""
    
    def test_get_current_user_authenticated(self, authenticated_client, test_user_data):
        """Test de récupération des infos utilisateur connecté"""
        response = authenticated_client.get("/api/auth/me")
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == test_user_data["username"]
        assert data["email"] == test_user_data["email"]
        assert data["is_active"] is True
    
    def test_get_current_user_unauthenticated(self, client):
        """Test de récupération des infos sans authentification"""
        response = client.get("/api/auth/me")
        
        assert response.status_code == 401


class TestPasswordGeneration:
    """Tests pour la génération de mots de passe via l'API"""
    
    def test_generate_password_authenticated(self, authenticated_client):
        """Test de génération de mot de passe pour utilisateur connecté"""
        request_data = {
            "length": 20,
            "include_uppercase": True,
            "include_lowercase": True,
            "include_numbers": True,
            "include_symbols": True
        }
        
        response = authenticated_client.post("/api/auth/generate-password", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "password" in data
        assert "length" in data
        assert "strength_score" in data
        assert data["length"] == 20
        assert len(data["password"]) == 20
        assert data["strength_score"] > 0
    
    def test_generate_password_unauthenticated(self, client):
        """Test de génération de mot de passe sans authentification"""
        request_data = {
            "length": 16,
            "include_uppercase": True,
            "include_lowercase": True,
            "include_numbers": True,
            "include_symbols": True
        }
        
        response = client.post("/api/auth/generate-password", json=request_data)
        assert response.status_code == 401
    
    def test_generate_password_invalid_length(self, authenticated_client):
        """Test de génération avec longueur invalide"""
        request_data = {
            "length": 2,  # Trop court
            "include_uppercase": True,
            "include_lowercase": True,
            "include_numbers": True,
            "include_symbols": True
        }
        
        response = authenticated_client.post("/api/auth/generate-password", json=request_data)
        assert response.status_code == 422  # Validation error
    
    def test_generate_password_no_characters(self, authenticated_client):
        """Test de génération sans aucun type de caractère"""
        request_data = {
            "length": 16,
            "include_uppercase": False,
            "include_lowercase": False,
            "include_numbers": False,
            "include_symbols": False
        }
        
        response = authenticated_client.post("/api/auth/generate-password", json=request_data)
        assert response.status_code == 400