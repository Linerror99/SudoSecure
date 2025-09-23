-- Script d'initialisation de la base de données PostgreSQL
-- Ce script est exécuté automatiquement lors du premier démarrage

-- Créer des extensions nécessaires
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Créer l'utilisateur de l'application s'il n'existe pas
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_user WHERE usename = 'sudosecure') THEN
        CREATE USER sudosecure WITH PASSWORD 'sudosecure_password';
    END IF;
END
$$;

-- Accorder les privilèges nécessaires
GRANT ALL PRIVILEGES ON DATABASE sudosecure_db TO sudosecure;

-- Se connecter à la base de données
\c sudosecure_db

-- Accorder les privilèges sur le schéma public
GRANT ALL ON SCHEMA public TO sudosecure;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sudosecure;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sudosecure;

-- Configurer les privilèges par défaut pour les futurs objets
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO sudosecure;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO sudosecure;

-- Message de confirmation
\echo 'Base de données SudoSecure initialisée avec succès!'