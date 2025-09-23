import pytest


class TestCredentialCRUD:
    """Tests pour les opérations CRUD sur les identifiants"""
    
    def test_create_credential(self, authenticated_client, test_credential_data):
        """Test de création d'un identifiant"""
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == test_credential_data["title"]
        assert data["website_url"] == test_credential_data["website_url"]
        assert data["username"] == test_credential_data["username"]
        assert "id" in data
        assert "created_at" in data
        # Le mot de passe ne doit pas être dans la réponse
        assert "password" not in data
    
    def test_create_credential_unauthenticated(self, client, test_credential_data):
        """Test de création d'identifiant sans authentification"""
        response = client.post("/api/credentials/", json=test_credential_data)
        assert response.status_code == 401
    
    def test_create_credential_missing_title(self, authenticated_client, test_credential_data):
        """Test de création d'identifiant sans titre"""
        invalid_data = test_credential_data.copy()
        del invalid_data["title"]
        
        response = authenticated_client.post("/api/credentials/", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    def test_create_credential_missing_password(self, authenticated_client, test_credential_data):
        """Test de création d'identifiant sans mot de passe"""
        invalid_data = test_credential_data.copy()
        del invalid_data["password"]
        
        response = authenticated_client.post("/api/credentials/", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    def test_get_credentials_list(self, authenticated_client, test_credential_data):
        """Test de récupération de la liste des identifiants"""
        # Créer quelques identifiants
        for i in range(3):
            data = test_credential_data.copy()
            data["title"] = f"Test Service {i}"
            authenticated_client.post("/api/credentials/", json=data)
        
        # Récupérer la liste
        response = authenticated_client.get("/api/credentials/")
        
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert len(data["results"]) == 3
        assert data["total"] == 3
    
    def test_get_credentials_with_search(self, authenticated_client, test_credential_data):
        """Test de recherche d'identifiants"""
        # Créer des identifiants avec différents titres
        titles = ["Gmail", "Facebook", "Twitter", "LinkedIn"]
        for title in titles:
            data = test_credential_data.copy()
            data["title"] = title
            authenticated_client.post("/api/credentials/", json=data)
        
        # Rechercher "book"
        response = authenticated_client.get("/api/credentials/?search=book")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 1
        assert data["results"][0]["title"] == "Facebook"
    
    def test_get_credential_by_id(self, authenticated_client, test_credential_data):
        """Test de récupération d'un identifiant par ID"""
        # Créer un identifiant
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        credential_id = response.json()["id"]
        
        # Récupérer par ID
        response = authenticated_client.get(f"/api/credentials/{credential_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == credential_id
        assert data["title"] == test_credential_data["title"]
    
    def test_get_nonexistent_credential(self, authenticated_client):
        """Test de récupération d'un identifiant inexistant"""
        response = authenticated_client.get("/api/credentials/99999")
        assert response.status_code == 404
    
    def test_update_credential(self, authenticated_client, test_credential_data):
        """Test de mise à jour d'un identifiant"""
        # Créer un identifiant
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        credential_id = response.json()["id"]
        
        # Mettre à jour
        update_data = {
            "title": "Updated Service",
            "website_url": "https://updated.example.com",
            "master_password": test_credential_data["master_password"]
        }
        response = authenticated_client.put(f"/api/credentials/{credential_id}", json=update_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "Updated Service"
        assert data["website_url"] == "https://updated.example.com"
    
    def test_update_nonexistent_credential(self, authenticated_client, test_credential_data):
        """Test de mise à jour d'un identifiant inexistant"""
        update_data = {
            "title": "Updated Service",
            "master_password": test_credential_data["master_password"]
        }
        response = authenticated_client.put("/api/credentials/99999", json=update_data)
        assert response.status_code == 404
    
    def test_delete_credential(self, authenticated_client, test_credential_data):
        """Test de suppression d'un identifiant"""
        # Créer un identifiant
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        credential_id = response.json()["id"]
        
        # Supprimer
        response = authenticated_client.delete(f"/api/credentials/{credential_id}")
        
        assert response.status_code == 200
        assert "supprimé" in response.json()["message"]
        
        # Vérifier que l'identifiant n'existe plus
        response = authenticated_client.get(f"/api/credentials/{credential_id}")
        assert response.status_code == 404
    
    def test_delete_nonexistent_credential(self, authenticated_client):
        """Test de suppression d'un identifiant inexistant"""
        response = authenticated_client.delete("/api/credentials/99999")
        assert response.status_code == 404


class TestCredentialPasswordReveal:
    """Tests pour la révélation des mots de passe chiffrés"""
    
    def test_reveal_password_correct_master_password(self, authenticated_client, test_credential_data):
        """Test de révélation avec le bon mot de passe maître"""
        # Créer un identifiant
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        credential_id = response.json()["id"]
        
        # Révéler le mot de passe
        reveal_data = {"master_password": test_credential_data["master_password"]}
        response = authenticated_client.post(
            f"/api/credentials/{credential_id}/reveal",
            json=reveal_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "password" in data
        assert data["password"] == test_credential_data["password"]
        assert data["title"] == test_credential_data["title"]
    
    def test_reveal_password_wrong_master_password(self, authenticated_client, test_credential_data):
        """Test de révélation avec un mauvais mot de passe maître"""
        # Créer un identifiant
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        credential_id = response.json()["id"]
        
        # Tentative de révélation avec un mauvais mot de passe maître
        reveal_data = {"master_password": "WrongMasterPassword123!"}
        response = authenticated_client.post(
            f"/api/credentials/{credential_id}/reveal",
            json=reveal_data
        )
        
        assert response.status_code == 401
    
    def test_reveal_password_missing_master_password(self, authenticated_client, test_credential_data):
        """Test de révélation sans mot de passe maître"""
        # Créer un identifiant
        response = authenticated_client.post("/api/credentials/", json=test_credential_data)
        credential_id = response.json()["id"]
        
        # Tentative de révélation sans mot de passe maître
        response = authenticated_client.post(
            f"/api/credentials/{credential_id}/reveal",
            json={}
        )
        
        assert response.status_code == 400
    
    def test_reveal_password_nonexistent_credential(self, authenticated_client, test_credential_data):
        """Test de révélation d'un identifiant inexistant"""
        reveal_data = {"master_password": test_credential_data["master_password"]}
        response = authenticated_client.post(
            "/api/credentials/99999/reveal",
            json=reveal_data
        )
        
        assert response.status_code == 404


class TestCredentialSecurity:
    """Tests de sécurité pour les identifiants"""
    
    def test_credentials_isolation_between_users(self, client, test_credential_data):
        """Test que les utilisateurs ne peuvent pas accéder aux identifiants des autres"""
        # Créer deux utilisateurs
        user1_data = {
            "email": "user1@example.com",
            "username": "user1",
            "master_password": "User1Password123!"
        }
        user2_data = {
            "email": "user2@example.com",
            "username": "user2",
            "master_password": "User2Password123!"
        }
        
        # Inscription et connexion utilisateur 1
        client.post("/api/auth/register", json=user1_data)
        login_response = client.post("/api/auth/login", json={
            "username": user1_data["username"],
            "master_password": user1_data["master_password"]
        })
        user1_token = login_response.json()["access_token"]
        
        # Inscription et connexion utilisateur 2
        client.post("/api/auth/register", json=user2_data)
        login_response = client.post("/api/auth/login", json={
            "username": user2_data["username"],
            "master_password": user2_data["master_password"]
        })
        user2_token = login_response.json()["access_token"]
        
        # Utilisateur 1 crée un identifiant
        credential_data = test_credential_data.copy()
        credential_data["master_password"] = user1_data["master_password"]
        
        response = client.post(
            "/api/credentials/",
            json=credential_data,
            headers={"Authorization": f"Bearer {user1_token}"}
        )
        credential_id = response.json()["id"]
        
        # Utilisateur 2 tente d'accéder à l'identifiant de l'utilisateur 1
        response = client.get(
            f"/api/credentials/{credential_id}",
            headers={"Authorization": f"Bearer {user2_token}"}
        )
        assert response.status_code == 404  # Ne doit pas trouver l'identifiant
        
        # Utilisateur 2 ne doit voir aucun identifiant dans sa liste
        response = client.get(
            "/api/credentials/",
            headers={"Authorization": f"Bearer {user2_token}"}
        )
        assert response.status_code == 200
        assert response.json()["total"] == 0