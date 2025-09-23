# Guide de Sécurité - SudoSecure

Ce document détaille les mesures de sécurité implémentées dans SudoSecure et les bonnes pratiques à suivre.

## 🔒 Architecture de Sécurité

### Chiffrement des Données
- **AES-256-GCM** : Chiffrement symétrique pour tous les mots de passe stockés
- **Clés dérivées** : Utilisation de PBKDF2 pour dériver les clés de chiffrement
- **Salt unique** : Chaque mot de passe a son propre salt
- **IV/Nonce aléatoire** : Génération aléatoire pour chaque opération de chiffrement

### Hachage des Mots de Passe
- **Argon2id** : Algorithme de hachage résistant aux attaques par force brute
- **Paramètres optimisés** : Configuration résistante aux attaques ASIC/GPU
- **Salt aléatoire** : Salt unique de 32 bytes pour chaque mot de passe

### Authentification
- **JWT (JSON Web Tokens)** : Gestion sécurisée des sessions
- **Expiration courte** : Tokens avec durée de vie limitée (30 minutes par défaut)
- **Révocation** : Possibilité de révoquer les tokens actifs
- **2FA TOTP** : Authentification à deux facteurs basée sur le temps

## 🛡️ Mesures de Protection

### Protection contre les Attaques

#### Force Brute
- Limitation du nombre de tentatives de connexion
- Verrouillage temporaire des comptes après échec
- Délai progressif entre les tentatives

#### Injection SQL
- Utilisation d'ORM (SQLAlchemy) avec requêtes paramétrées
- Validation stricte des entrées utilisateur
- Échappement automatique des caractères spéciaux

#### XSS (Cross-Site Scripting)
- Validation et échappement des données côté frontend
- Headers de sécurité appropriés
- Content Security Policy (CSP)

#### CSRF (Cross-Site Request Forgery)
- Tokens CSRF pour les actions sensibles
- Validation de l'origine des requêtes
- SameSite cookies

### Headers de Sécurité
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## 🔐 Configuration Sécurisée

### Variables d'Environnement Sensibles

#### SECRET_KEY
```bash
# Générer une clé forte (32+ caractères)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

#### Mots de Passe Base de Données
```bash
# Critères pour un mot de passe fort :
# - 16+ caractères
# - Lettres majuscules et minuscules
# - Chiffres et caractères spéciaux
# - Pas de mots du dictionnaire
```

### Configuration Production

#### Base de Données
```yaml
# docker-compose.prod.yml
postgres:
  environment:
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
  volumes:
    - postgres_data:/var/lib/postgresql/data
  networks:
    - internal  # Réseau interne uniquement
```

#### Application
```yaml
backend:
  environment:
    ENVIRONMENT: production
    DEBUG: false
    LOG_LEVEL: WARNING
  restart: unless-stopped
```

## 🚀 Déploiement Sécurisé

### Configuration HTTPS

#### Certificats SSL/TLS
```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/sudosecure.crt;
    ssl_certificate_key /etc/ssl/private/sudosecure.key;
    
    # Configuration SSL moderne
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
}
```

### Pare-feu et Réseau
```bash
# Exemple de règles UFW
ufw deny incoming
ufw allow outgoing
ufw allow ssh
ufw allow 443/tcp  # HTTPS uniquement
ufw enable
```

### Conteneurs Sécurisés
```dockerfile
# Utilisateur non-root
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
USER appuser

# Pas de shell dans l'image finale
RUN rm -rf /bin/sh /bin/bash
```

## 📊 Monitoring et Audit

### Logs de Sécurité
Les événements suivants sont enregistrés :
- Tentatives de connexion (succès/échec)
- Création/modification/suppression d'identifiants
- Changements de configuration 2FA
- Accès aux mots de passe (révélation)
- Tentatives d'accès non autorisé

### Métriques à Surveiller
- Nombre de tentatives de connexion échouées
- Fréquence d'utilisation par utilisateur
- Temps de réponse de l'API
- Utilisation des ressources système

### Alertes Recommandées
- Plus de 10 échecs de connexion en 5 minutes
- Accès depuis une nouvelle IP
- Modification de mot de passe maître
- Désactivation de la 2FA

## 🔄 Maintenance Sécurisée

### Mises à Jour
```bash
# Planifiez des mises à jour régulières
# 1. Sauvegarde complète
docker-compose exec postgres pg_dump -U sudosecure sudosecure_db > backup.sql

# 2. Mise à jour du code
git pull origin main

# 3. Reconstruction des images
docker-compose down
docker-compose up -d --build

# 4. Vérification des logs
docker-compose logs --tail=50
```

### Sauvegardes Chiffrées
```bash
# Sauvegarde avec chiffrement GPG
docker-compose exec postgres pg_dump -U sudosecure sudosecure_db | \
gzip | \
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
--output backup-$(date +%Y%m%d).sql.gz.gpg
```

### Rotation des Clés
1. **JWT Secret Key** : Rotation mensuelle recommandée
2. **Clés de chiffrement** : Rotation annuelle ou après incident
3. **Certificats SSL** : Renouvellement avant expiration

## ✅ Checklist de Sécurité

### Avant Déploiement
- [ ] Tous les mots de passe par défaut changés
- [ ] SECRET_KEY unique généré
- [ ] HTTPS configuré
- [ ] Certificats SSL valides
- [ ] Pare-feu configuré
- [ ] Logs de sécurité activés
- [ ] Monitoring configuré
- [ ] Sauvegardes testées

### Maintenance Régulière
- [ ] Mises à jour de sécurité appliquées
- [ ] Logs de sécurité vérifiés
- [ ] Métriques analysées
- [ ] Sauvegardes vérifiées
- [ ] Tests de récupération effectués
- [ ] Audit des accès utilisateurs

### En Cas d'Incident
- [ ] Isolation immédiate du système
- [ ] Analyse des logs
- [ ] Changement de toutes les clés
- [ ] Notification des utilisateurs
- [ ] Rapport d'incident rédigé
- [ ] Mesures correctives implémentées

## 🆘 Réponse aux Incidents

### Procédure d'Urgence
1. **Isolation** : Couper l'accès réseau si nécessaire
2. **Évaluation** : Déterminer l'étendue de l'incident
3. **Containment** : Empêcher la propagation
4. **Investigation** : Analyser les logs et traces
5. **Récupération** : Restaurer le service sécurisé
6. **Post-mortem** : Analyser et améliorer

### Contacts d'Urgence
- Administrateur système : [contact]
- Équipe de sécurité : [contact]
- Responsable produit : [contact]

---

**⚠️ Rappel Important** : La sécurité est un processus continu. Ce guide doit être révisé et mis à jour régulièrement selon l'évolution des menaces et des bonnes pratiques.