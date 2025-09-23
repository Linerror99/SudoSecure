# 🔐 SudoSecure - Gestionnaire de Mots de Passe Sécurisé

SudoSecure est un gestionnaire de mots de passe moderne et sécurisé développé avec FastAPI et une interface web responsive. Il offre un chiffrement de niveau militaire, une authentification à deux facteurs et une architecture conteneurisée pour un déploiement facile.

## ✨ Fonctionnalités

### 🔒 Sécurité Avancée
- **Chiffrement AES-256** : Tous les mots de passe sont chiffrés avec AES-256
- **Hachage Argon2** : Les mots de passe maîtres sont hachés avec Argon2
- **Authentification 2FA** : Support TOTP avec codes de récupération
- **JWT sécurisé** : Gestion des sessions avec JSON Web Tokens
- **Isolation des données** : Séparation complète entre utilisateurs

### 💻 Interface Utilisateur
- **Design moderne** : Interface responsive avec Bootstrap 5
- **Dashboard intuitif** : Gestion facile de vos identifiants
- **Recherche instantanée** : Trouvez rapidement vos mots de passe
- **Générateur intégré** : Création de mots de passe sécurisés
- **Copie sécurisée** : Copie en un clic avec feedback visuel

### 🛠 Technologies
- **Backend** : FastAPI (Python 3.11)
- **Frontend** : HTML5, CSS3, JavaScript (Vanilla)
- **Base de données** : PostgreSQL 15
- **Cache** : Redis (optionnel)
- **Conteneurisation** : Docker & Docker Compose

## 🚀 Installation Rapide

### Prérequis
- Docker et Docker Compose
- Git

### Lancement avec Docker Compose

1. **Clonez le projet**
```bash
git clone <repository-url>
cd SudoSecure
```

2. **Configurez l'environnement**
```bash
cp .env.example .env
# Éditez le fichier .env avec vos propres valeurs sécurisées
```

3. **Lancez l'application**
```bash
docker-compose up -d
```

4. **Accédez à l'application**
- Frontend : http://localhost:8080
- API Backend : http://localhost:8000
- Documentation API : http://localhost:8000/docs

## 📁 Architecture du Projet

```
SudoSecure/
├── backend/                    # API FastAPI
│   ├── app/
│   │   ├── api/               # Endpoints API
│   │   ├── core/              # Configuration et sécurité
│   │   ├── models/            # Modèles de base de données
│   │   ├── schemas/           # Schémas Pydantic
│   │   ├── services/          # Logique métier
│   │   └── main.py           # Point d'entrée
│   ├── tests/                # Tests unitaires
│   ├── Dockerfile           # Image Docker backend
│   └── requirements.txt     # Dépendances Python
├── frontend/                 # Interface web
│   ├── static/
│   │   ├── css/             # Styles CSS
│   │   └── js/              # JavaScript
│   ├── index.html           # Page principale
│   ├── Dockerfile           # Image Docker frontend
│   └── nginx.conf           # Configuration Nginx
├── docker/                  # Configuration Docker
├── docker-compose.yml       # Orchestration des services
└── README.md               # Cette documentation
```

## 🔧 Configuration

### Variables d'Environnement

Copiez le fichier `.env.example` vers `.env` et configurez :

```env
# Base de données
POSTGRES_DB=sudosecure_db
POSTGRES_USER=sudosecure
POSTGRES_PASSWORD=your_secure_password

# JWT
SECRET_KEY=your-super-secret-jwt-key-32-chars-min
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
ENVIRONMENT=production
DEBUG=false
```

### Configuration de Production

Pour un déploiement en production :

1. **Utilisez le fichier de production**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

2. **Configurez HTTPS**
- Placez vos certificats SSL dans le dossier `certs/`
- Modifiez `nginx-prod.conf` selon vos besoins

3. **Sécurisez votre base de données**
- Changez tous les mots de passe par défaut
- Configurez des sauvegardes automatiques
- Limitez l'accès réseau

## 📖 Utilisation

### Première Connexion

1. **Créez un compte** avec un mot de passe maître fort
2. **Activez la 2FA** (recommandé) dans les paramètres de sécurité
3. **Ajoutez vos premiers identifiants**

### Gestion des Identifiants

- **Ajouter** : Cliquez sur "Ajouter" et remplissez le formulaire
- **Rechercher** : Utilisez la barre de recherche pour filtrer
- **Modifier** : Cliquez sur l'icône crayon
- **Supprimer** : Cliquez sur l'icône poubelle
- **Révéler** : Cliquez sur "Voir" et entrez votre mot de passe maître

### Générateur de Mots de Passe

1. Accédez à l'onglet "Générateur"
2. Configurez les options (longueur, types de caractères)
3. Cliquez sur "Générer"
4. Copiez le mot de passe généré

## 🔍 API Documentation

### Endpoints Principaux

#### Authentification
- `POST /api/auth/register` - Inscription
- `POST /api/auth/login` - Connexion
- `GET /api/auth/me` - Informations utilisateur
- `POST /api/auth/generate-password` - Génération de mot de passe

#### 2FA
- `POST /api/auth/2fa/setup` - Configuration 2FA
- `POST /api/auth/2fa/verify` - Vérification 2FA
- `DELETE /api/auth/2fa/disable` - Désactivation 2FA

#### Identifiants
- `GET /api/credentials/` - Liste des identifiants
- `POST /api/credentials/` - Création d'identifiant
- `GET /api/credentials/{id}` - Récupération d'identifiant
- `PUT /api/credentials/{id}` - Mise à jour d'identifiant
- `DELETE /api/credentials/{id}` - Suppression d'identifiant
- `POST /api/credentials/{id}/reveal` - Révélation du mot de passe

### Documentation Interactive

Accédez à http://localhost:8000/docs pour la documentation Swagger complète.

## 🧪 Tests

### Lancer les Tests

```bash
# Tests unitaires
cd backend
pip install -r requirements.txt
pytest

# Tests avec couverture
pytest --cov=app --cov-report=html

# Tests spécifiques
pytest tests/test_security.py -v
```

### Types de Tests

- **Tests de sécurité** : Chiffrement, hachage, génération
- **Tests d'authentification** : Inscription, connexion, JWT
- **Tests CRUD** : Opérations sur les identifiants
- **Tests d'isolation** : Sécurité entre utilisateurs

## 🐳 Développement

### Développement Local

1. **Backend**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

2. **Frontend**
```bash
cd frontend
# Servir avec un serveur web simple
python -m http.server 8080
```

3. **Base de données**
```bash
docker run --name postgres-dev -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres:15
```

### Structure des Commits

Utilisez des messages de commit descriptifs :
- `feat:` nouvelle fonctionnalité
- `fix:` correction de bug
- `sec:` amélioration de sécurité
- `docs:` documentation
- `test:` ajout de tests

## 🔐 Sécurité

### Bonnes Pratiques Implémentées

- ✅ Chiffrement AES-256 pour tous les mots de passe stockés
- ✅ Hachage Argon2 pour les mots de passe maîtres
- ✅ Authentification à deux facteurs (TOTP)
- ✅ JWT avec expiration pour les sessions
- ✅ Validation stricte des entrées
- ✅ Isolation complète des données utilisateur
- ✅ Headers de sécurité HTTP
- ✅ Protection CORS configurée
- ✅ Containers non-root
- ✅ Pas de secrets en dur dans le code

### Recommendations de Sécurité

1. **Changez tous les mots de passe par défaut**
2. **Utilisez HTTPS en production**
3. **Configurez des sauvegardes chiffrées**
4. **Mettez à jour régulièrement les dépendances**
5. **Surveillez les logs d'accès**
6. **Activez la 2FA pour tous les comptes**

## 📊 Monitoring

### Logs

Les logs sont accessibles via Docker :

```bash
# Logs de l'application
docker-compose logs backend

# Logs en temps réel
docker-compose logs -f frontend

# Logs de la base de données
docker-compose logs postgres
```

### Health Checks

- Backend : http://localhost:8000/health
- Frontend : http://localhost:8080/
- Base de données : via `docker-compose ps`

## 🤝 Contribution

### Comment Contribuer

1. **Fork** le projet
2. **Créez** une branche pour votre fonctionnalité
3. **Ajoutez** des tests pour votre code
4. **Assurez-vous** que tous les tests passent
5. **Soumettez** une Pull Request

### Standards de Code

- **Python** : Suivre PEP 8
- **JavaScript** : Utiliser ESLint
- **Tests** : Couverture minimum de 80%
- **Documentation** : Documenter les nouvelles fonctionnalités

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- [FastAPI](https://fastapi.tiangolo.com/) pour le framework backend
- [Bootstrap](https://getbootstrap.com/) pour l'interface utilisateur
- [PostgreSQL](https://www.postgresql.org/) pour la base de données
- [Docker](https://www.docker.com/) pour la conteneurisation

## 📞 Support

Si vous rencontrez des problèmes :

1. Consultez la [documentation](#api-documentation)
2. Vérifiez les [logs](#logs)
3. Recherchez dans les [issues existantes](../../issues)
4. Créez une [nouvelle issue](../../issues/new) si nécessaire

---

**⚠️ Important** : Ce gestionnaire de mots de passe a été conçu avec la sécurité comme priorité absolue. Cependant, assurez-vous de suivre les meilleures pratiques de déploiement et de maintenance pour garantir la sécurité de vos données.
