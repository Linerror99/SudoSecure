# Frontend Dockerfile
FROM nginx:alpine

# Installer curl pour le healthcheck
RUN apk add --no-cache curl

# Supprimer la configuration par défaut de Nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copier la configuration personnalisée de Nginx
COPY nginx.conf /etc/nginx/conf.d/

# Copier les fichiers statiques
COPY . /usr/share/nginx/html/

# Créer un fichier de configuration nginx sans directive user
RUN sed -i '1i# Automatically generated configuration' /etc/nginx/nginx.conf

# Ajuster les permissions pour l'utilisateur nginx existant
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown nginx:nginx /var/run/nginx.pid

# Exposer le port
EXPOSE 80

# Passer à l'utilisateur nginx pour la sécurité
USER nginx

# Vérification de santé
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/ || exit 1

# Commande par défaut
CMD ["nginx", "-g", "daemon off;"]