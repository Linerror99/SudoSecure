# Guide de Démarrage Rapide - SudoSecure

Ce guide vous permettra de démarrer SudoSecure en quelques minutes.

## 🚀 Installation Express

### 1. Prérequis
Assurez-vous d'avoir installé :
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Git](https://git-scm.com/downloads)

### 2. Téléchargement
```bash
git clone <votre-repository-url>
cd SudoSecure
```

### 3. Configuration
```bash
# Copiez le fichier de configuration
cp .env.example .env

# Modifiez les variables importantes
nano .env  # ou votre éditeur préféré
```

**⚠️ Important** : Changez au minimum ces valeurs dans `.env` :
- `POSTGRES_PASSWORD` : Un mot de passe fort pour la base de données
- `SECRET_KEY` : Une clé secrète de 32 caractères minimum pour JWT

### 4. Lancement
```bash
# Démarrage des services
docker-compose up -d

# Vérification du statut
docker-compose ps
```

### 5. Accès
- **Application** : http://localhost:8080
- **API Documentation** : http://localhost:8000/docs
- **Backend API** : http://localhost:8000

## 📋 Première Utilisation

### Créer votre premier compte
1. Ouvrez http://localhost:8080
2. Cliquez sur "S'inscrire"
3. Créez un compte avec un mot de passe maître fort
4. Activez la 2FA (recommandé)

### Ajouter vos premiers identifiants
1. Connectez-vous à votre tableau de bord
2. Cliquez sur "Ajouter un identifiant"
3. Remplissez les informations (service, nom d'utilisateur, mot de passe)
4. Sauvegardez

### Utiliser le générateur de mots de passe
1. Allez dans l'onglet "Générateur"
2. Configurez les options selon vos besoins
3. Générez et copiez le mot de passe

## 🔧 Commandes Utiles

```bash
# Voir les logs
docker-compose logs backend
docker-compose logs frontend
docker-compose logs postgres

# Redémarrer un service
docker-compose restart backend

# Mise à jour
git pull
docker-compose down
docker-compose up -d --build

# Sauvegarde de la base de données
docker-compose exec postgres pg_dump -U sudosecure sudosecure_db > backup.sql

# Arrêt complet
docker-compose down
```

## 🆘 Résolution de Problèmes

### Le frontend ne se charge pas
```bash
# Vérifiez les logs
docker-compose logs frontend

# Redémarrez le service
docker-compose restart frontend
```

### Erreur de base de données
```bash
# Vérifiez que PostgreSQL fonctionne
docker-compose ps postgres

# Consultez les logs
docker-compose logs postgres

# Redémarrez si nécessaire
docker-compose restart postgres
```

### Problème de port occupé
Si le port 8080 ou 8000 est déjà utilisé, modifiez dans `docker-compose.yml` :
```yaml
ports:
  - "8081:80"  # Pour le frontend
  - "8001:8000"  # Pour le backend
```

## 🔐 Sécurité Rapide

### Changements obligatoires pour la production
1. **Mots de passe** : Changez tous les mots de passe par défaut
2. **SECRET_KEY** : Générez une clé secrète unique
3. **HTTPS** : Configurez SSL/TLS
4. **Firewall** : Limitez l'accès aux ports

### Génération de clé secrète
```bash
# Générer une clé secrète forte
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## 📞 Besoin d'aide ?

- 📖 Documentation complète : [README.md](README.md)
- 🐛 Problèmes : Créez une issue sur GitHub
- 💬 Questions : Consultez la documentation API

---

**🎉 Félicitations !** Votre gestionnaire de mots de passe SudoSecure est maintenant opérationnel !