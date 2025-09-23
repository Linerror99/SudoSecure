import pytest
from app.core.security import security_manager


class TestPasswordHashing:
    """Tests pour le hachage et la vérification des mots de passe"""
    
    def test_hash_password(self):
        """Test du hachage d'un mot de passe"""
        password = "TestPassword123!"
        hashed = security_manager.hash_password(password)
        
        assert hashed != password  # Le hash ne doit pas être le mot de passe en clair
        assert len(hashed) > 0  # Le hash ne doit pas être vide
        assert hashed.startswith("$argon2")  # Doit utiliser Argon2
    
    def test_verify_password_correct(self):
        """Test de vérification avec le bon mot de passe"""
        password = "TestPassword123!"
        hashed = security_manager.hash_password(password)
        
        assert security_manager.verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test de vérification avec un mauvais mot de passe"""
        password = "TestPassword123!"
        wrong_password = "WrongPassword456!"
        hashed = security_manager.hash_password(password)
        
        assert security_manager.verify_password(wrong_password, hashed) is False
    
    def test_hash_consistency(self):
        """Test que le même mot de passe produit des hash différents (sel aléatoire)"""
        password = "TestPassword123!"
        hash1 = security_manager.hash_password(password)
        hash2 = security_manager.hash_password(password)
        
        assert hash1 != hash2  # Les hash doivent être différents
        assert security_manager.verify_password(password, hash1) is True
        assert security_manager.verify_password(password, hash2) is True


class TestPasswordEncryption:
    """Tests pour le chiffrement et déchiffrement des mots de passe"""
    
    def test_derive_key_from_password(self):
        """Test de dérivation de clé à partir d'un mot de passe"""
        password = "TestMasterPassword123!"
        salt = security_manager.generate_salt()
        
        key = security_manager.derive_key_from_password(password, salt)
        
        assert len(key) == 44  # Clé base64 de 32 bytes
        
        # Même mot de passe et sel doivent donner la même clé
        key2 = security_manager.derive_key_from_password(password, salt)
        assert key == key2
    
    def test_generate_salt(self):
        """Test de génération de sel"""
        salt1 = security_manager.generate_salt()
        salt2 = security_manager.generate_salt()
        
        assert len(salt1) == 16  # 16 bytes
        assert len(salt2) == 16
        assert salt1 != salt2  # Les sels doivent être différents
    
    def test_encrypt_decrypt_password(self):
        """Test de chiffrement et déchiffrement"""
        password = "TestPasswordToEncrypt123!"
        master_password = "MasterPassword123!"
        salt = security_manager.generate_salt()
        
        encryption_key = security_manager.derive_key_from_password(master_password, salt)
        
        # Chiffrer
        encrypted = security_manager.encrypt_password(password, encryption_key)
        assert encrypted != password
        assert len(encrypted) > 0
        
        # Déchiffrer
        decrypted = security_manager.decrypt_password(encrypted, encryption_key)
        assert decrypted == password
    
    def test_decrypt_with_wrong_key(self):
        """Test de déchiffrement avec une mauvaise clé"""
        password = "TestPasswordToEncrypt123!"
        master_password = "MasterPassword123!"
        wrong_master_password = "WrongMasterPassword456!"
        salt = security_manager.generate_salt()
        
        encryption_key = security_manager.derive_key_from_password(master_password, salt)
        wrong_key = security_manager.derive_key_from_password(wrong_master_password, salt)
        
        encrypted = security_manager.encrypt_password(password, encryption_key)
        
        # Tentative de déchiffrement avec une mauvaise clé
        with pytest.raises(ValueError, match="Impossible de déchiffrer"):
            security_manager.decrypt_password(encrypted, wrong_key)


class TestPasswordGeneration:
    """Tests pour la génération de mots de passe sécurisés"""
    
    def test_generate_default_password(self):
        """Test de génération avec paramètres par défaut"""
        password = security_manager.generate_secure_password()
        
        assert len(password) == 16  # Longueur par défaut
        assert any(c.islower() for c in password)  # Minuscules
        assert any(c.isupper() for c in password)  # Majuscules
        assert any(c.isdigit() for c in password)  # Chiffres
        assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)  # Symboles
    
    def test_generate_custom_length(self):
        """Test de génération avec longueur personnalisée"""
        password = security_manager.generate_secure_password(length=24)
        assert len(password) == 24
    
    def test_generate_lowercase_only(self):
        """Test de génération avec minuscules seulement"""
        password = security_manager.generate_secure_password(
            length=20,
            include_uppercase=False,
            include_numbers=False,
            include_symbols=False
        )
        
        assert len(password) == 20
        assert all(c.islower() for c in password)
    
    def test_generate_uppercase_only(self):
        """Test de génération avec majuscules seulement"""
        password = security_manager.generate_secure_password(
            length=20,
            include_lowercase=False,
            include_numbers=False,
            include_symbols=False
        )
        
        assert len(password) == 20
        assert all(c.isupper() for c in password)
    
    def test_generate_numbers_only(self):
        """Test de génération avec chiffres seulement"""
        password = security_manager.generate_secure_password(
            length=20,
            include_lowercase=False,
            include_uppercase=False,
            include_symbols=False
        )
        
        assert len(password) == 20
        assert all(c.isdigit() for c in password)
    
    def test_generate_symbols_only(self):
        """Test de génération avec symboles seulement"""
        password = security_manager.generate_secure_password(
            length=20,
            include_lowercase=False,
            include_uppercase=False,
            include_numbers=False
        )
        
        assert len(password) == 20
        assert all(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    def test_generate_no_characters_selected(self):
        """Test d'erreur quand aucun type de caractère n'est sélectionné"""
        with pytest.raises(ValueError, match="Au moins un type de caractère"):
            security_manager.generate_secure_password(
                include_lowercase=False,
                include_uppercase=False,
                include_numbers=False,
                include_symbols=False
            )
    
    def test_password_randomness(self):
        """Test que les mots de passe générés sont aléatoires"""
        passwords = [
            security_manager.generate_secure_password()
            for _ in range(10)
        ]
        
        # Tous les mots de passe doivent être différents
        assert len(set(passwords)) == len(passwords)