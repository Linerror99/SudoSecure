// Configuration de l'API
const API_BASE_URL = 'http://localhost:8000/api';

// État global de l'application
const appState = {
    currentUser: null,
    authToken: null,
    credentials: [],
    currentPage: 1,
    totalPages: 1,
    searchQuery: '',
    currentCredentialId: null
};

// Utilitaires
const utils = {
    // Échapper le HTML pour prévenir les XSS
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    // Valider et nettoyer les URLs
    validateUrl(url) {
        if (!url) return null;
        try {
            const parsed = new URL(url);
            // Autoriser seulement http et https
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                return null;
            }
            return parsed.href;
        } catch {
            return null;
        }
    },

    // Afficher/masquer les sections
    showSection(sectionId) {
        document.querySelectorAll('#dashboard > div > div[id$="Section"]').forEach(section => {
            section.style.display = 'none';
        });
        document.getElementById(sectionId).style.display = 'block';
        
        // Mettre à jour les onglets actifs
        document.querySelectorAll('.list-group-item').forEach(tab => {
            tab.classList.remove('active');
        });
        document.getElementById(sectionId.replace('Section', 'Tab')).classList.add('active');
    },

    // Afficher une notification toast
    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        const toastId = 'toast-' + Date.now();
        
        const toastHtml = `
            <div id="${toastId}" class="toast toast-${type}" role="alert">
                <div class="toast-header">
                    <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'} me-2"></i>
                    <strong class="me-auto">SudoSecure</strong>
                    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">${message}</div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHtml);
        const toast = new bootstrap.Toast(document.getElementById(toastId));
        toast.show();
        
        // Supprimer le toast après fermeture
        document.getElementById(toastId).addEventListener('hidden.bs.toast', function() {
            this.remove();
        });
    },

    // Copier du texte dans le presse-papiers
    async copyToClipboard(text, button = null) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast('Copié dans le presse-papiers', 'success');
            
            if (button) {
                button.classList.add('copy-success');
                setTimeout(() => button.classList.remove('copy-success'), 300);
            }
        } catch (err) {
            this.showToast('Erreur lors de la copie', 'error');
        }
    },

    // Formater une date
    formatDate(dateString) {
        return new Date(dateString).toLocaleDateString('fr-FR', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    // Calculer la force d'un mot de passe
    calculatePasswordStrength(password) {
        let score = 0;
        let feedback = [];

        if (password.length >= 8) score += 25;
        else feedback.push('Au moins 8 caractères');

        if (password.length >= 12) score += 25;
        else if (score > 0) feedback.push('Au moins 12 caractères recommandés');

        if (/[a-z]/.test(password)) score += 10;
        else feedback.push('Minuscules');

        if (/[A-Z]/.test(password)) score += 10;
        else feedback.push('Majuscules');

        if (/[0-9]/.test(password)) score += 10;
        else feedback.push('Chiffres');

        if (/[^A-Za-z0-9]/.test(password)) score += 20;
        else feedback.push('Caractères spéciaux');

        let strength = 'weak';
        if (score >= 90) strength = 'very-strong';
        else if (score >= 70) strength = 'strong';
        else if (score >= 50) strength = 'medium';

        return { score, strength, feedback };
    },

    // Valider le mot de passe selon les critères requis
    validatePasswordCriteria(password) {
        return {
            minLength: password.length >= 12,
            hasLowercase: /[a-z]/.test(password),
            hasUppercase: /[A-Z]/.test(password),
            hasNumbers: /[0-9]/.test(password),
            hasSymbols: /[^A-Za-z0-9]/.test(password)
        };
    },

    // Vérifier si tous les critères sont remplis
    isPasswordValid(password) {
        const criteria = this.validatePasswordCriteria(password);
        return Object.values(criteria).every(Boolean);
    },

    // Mettre à jour l'affichage des critères de mot de passe
    updatePasswordCriteria(password, containerElement) {
        const criteria = this.validatePasswordCriteria(password);
        
        const criteriaHtml = `
            <div class="password-criteria mt-2">
                <small class="text-muted d-block mb-1">Le mot de passe doit contenir :</small>
                <div class="criteria-list">
                    <div class="criteria-item ${criteria.minLength ? 'valid' : 'invalid'}">
                        <i class="bi ${criteria.minLength ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-danger'}"></i>
                        Au moins 12 caractères
                    </div>
                    <div class="criteria-item ${criteria.hasLowercase ? 'valid' : 'invalid'}">
                        <i class="bi ${criteria.hasLowercase ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-danger'}"></i>
                        Lettres minuscules (a-z)
                    </div>
                    <div class="criteria-item ${criteria.hasUppercase ? 'valid' : 'invalid'}">
                        <i class="bi ${criteria.hasUppercase ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-danger'}"></i>
                        Lettres majuscules (A-Z)
                    </div>
                    <div class="criteria-item ${criteria.hasNumbers ? 'valid' : 'invalid'}">
                        <i class="bi ${criteria.hasNumbers ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-danger'}"></i>
                        Chiffres (0-9)
                    </div>
                    <div class="criteria-item ${criteria.hasSymbols ? 'valid' : 'invalid'}">
                        <i class="bi ${criteria.hasSymbols ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-danger'}"></i>
                        Caractères spéciaux (!@#$%^&*...)
                    </div>
                </div>
            </div>
        `;
        
        containerElement.innerHTML = criteriaHtml;
        return this.isPasswordValid(password);
    },

    // Mettre à jour la barre de force du mot de passe
    updatePasswordStrength(password, barElement, textElement) {
        const { score, strength, feedback } = this.calculatePasswordStrength(password);
        
        barElement.style.width = score + '%';
        barElement.className = `progress-bar strength-${strength}`;
        
        const strengthTexts = {
            'weak': 'Faible',
            'medium': 'Moyen',
            'strong': 'Fort',
            'very-strong': 'Très fort'
        };
        
        textElement.textContent = `${strengthTexts[strength]} (${score}%)`;
        if (feedback.length > 0) {
            textElement.textContent += ` - Manque: ${feedback.join(', ')}`;
        }
    },

    // Valider un email
    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Débounce pour les recherches
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// API Service
const apiService = {
    // Effectuer une requête API
    async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };

        if (appState.authToken) {
            defaultOptions.headers['Authorization'] = `Bearer ${appState.authToken}`;
        }

        const finalOptions = { ...defaultOptions, ...options };
        if (finalOptions.body && typeof finalOptions.body === 'object') {
            finalOptions.body = JSON.stringify(finalOptions.body);
        }

        try {
            const response = await fetch(url, finalOptions);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Erreur de requête');
            }

            return data;
        } catch (error) {
            console.error('Erreur API:', error);
            // Améliorer l'affichage des erreurs
            if (error.message && error.message !== '[object Object]') {
                throw error;
            } else {
                throw new Error('Erreur de connexion au serveur');
            }
        }
    },

    // Méthodes d'authentification
    async register(userData) {
        return await this.request('/auth/register', {
            method: 'POST',
            body: userData
        });
    },

    async login(credentials) {
        return await this.request('/auth/login', {
            method: 'POST',
            body: credentials
        });
    },

    async getCurrentUser() {
        return await this.request('/auth/me');
    },

    async generatePassword(options) {
        return await this.request('/auth/generate-password', {
            method: 'POST',
            body: options
        });
    },

    // Méthodes 2FA
    async setup2FA() {
        return await this.request('/auth/2fa/setup', {
            method: 'POST'
        });
    },

    async verify2FA(code) {
        return await this.request('/auth/2fa/verify', {
            method: 'POST',
            body: { totp_code: code }
        });
    },

    async disable2FA() {
        return await this.request('/auth/2fa/disable', {
            method: 'DELETE'
        });
    },

    // Méthodes pour les identifiants
    async getCredentials(page = 1, search = '') {
        const params = new URLSearchParams({ page: page.toString(), per_page: '20' });
        if (search) params.append('search', search);
        return await this.request(`/credentials?${params}`);
    },

    async getCredential(id) {
        return await this.request(`/credentials/${id}`);
    },

    async createCredential(credentialData) {
        return await this.request('/credentials', {
            method: 'POST',
            body: credentialData
        });
    },

    async updateCredential(id, credentialData) {
        return await this.request(`/credentials/${id}`, {
            method: 'PUT',
            body: credentialData
        });
    },

    async deleteCredential(id) {
        return await this.request(`/credentials/${id}`, {
            method: 'DELETE'
        });
    },

    async revealPassword(id, masterPassword) {
        return await this.request(`/credentials/${id}/reveal`, {
            method: 'POST',
            body: { master_password: masterPassword }
        });
    }
};

// Gestionnaire d'authentification
const authManager = {
    init() {
        // Vérifier si un token existe dans le localStorage
        const token = localStorage.getItem('sudosecure_token');
        if (token) {
            appState.authToken = token;
            this.checkAuthStatus();
        }

        this.bindEvents();
    },

    bindEvents() {
        // Formulaire de connexion
        document.getElementById('loginForm').addEventListener('submit', this.handleLogin.bind(this));
        
        // Formulaire d'inscription
        document.getElementById('registerForm').addEventListener('submit', this.handleRegister.bind(this));
        
        // Basculer entre connexion et inscription
        document.getElementById('showRegister').addEventListener('click', () => {
            document.getElementById('loginPage').style.display = 'none';
            document.getElementById('registerPage').style.display = 'block';
        });
        
        document.getElementById('showLogin').addEventListener('click', () => {
            document.getElementById('registerPage').style.display = 'none';
            document.getElementById('loginPage').style.display = 'block';
        });
        
        // Déconnexion
        document.getElementById('logoutBtn').addEventListener('click', this.logout.bind(this));
        
        // Boutons pour afficher/masquer les mots de passe
        this.bindPasswordToggle('toggleLoginPassword', 'loginPassword');
        this.bindPasswordToggle('toggleRegisterPassword', 'registerPassword');
        
        // Validation en temps réel du mot de passe d'inscription
        const registerPasswordInput = document.getElementById('registerPassword');
        const criteriaContainer = document.getElementById('passwordCriteriaContainer');
        const registerSubmitBtn = document.querySelector('#registerForm button[type="submit"]');
        
        registerPasswordInput.addEventListener('input', (e) => {
            const password = e.target.value;
            const isValid = utils.updatePasswordCriteria(password, criteriaContainer);
            
            // Activer/désactiver le bouton d'inscription
            if (registerSubmitBtn) {
                registerSubmitBtn.disabled = !isValid || password.length === 0;
                if (isValid && password.length > 0) {
                    registerSubmitBtn.classList.remove('btn-secondary');
                    registerSubmitBtn.classList.add('btn-primary');
                } else {
                    registerSubmitBtn.classList.remove('btn-primary');
                    registerSubmitBtn.classList.add('btn-secondary');
                }
            }
        });
    },

    bindPasswordToggle(buttonId, inputId) {
        document.getElementById(buttonId).addEventListener('click', function() {
            const input = document.getElementById(inputId);
            const icon = this.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'bi bi-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'bi bi-eye';
            }
        });
    },

    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        const totpCode = document.getElementById('totpCode').value;
        
        try {
            const credentials = { username, master_password: password };
            if (totpCode) credentials.totp_code = totpCode;
            
            const response = await apiService.login(credentials);
            
            this.setAuthData(response.access_token, response.user);
            this.showDashboard();
            utils.showToast('Connexion réussie', 'success');
            
        } catch (error) {
            if (error.message.includes('2FA')) {
                document.getElementById('totpSection').style.display = 'block';
                utils.showToast('Code 2FA requis', 'info');
            } else {
                utils.showToast(error.message, 'error');
            }
        }
    },

    async handleRegister(e) {
        e.preventDefault();
        
        const email = document.getElementById('registerEmail').value;
        const username = document.getElementById('registerUsername').value;
        const password = document.getElementById('registerPassword').value;
        
        if (!utils.validateEmail(email)) {
            utils.showToast('Email invalide', 'error');
            return;
        }
        
        if (!utils.isPasswordValid(password)) {
            utils.showToast('Le mot de passe ne respecte pas tous les critères requis', 'error');
            return;
        }
        
        try {
            await apiService.register({
                email,
                username,
                master_password: password
            });
            
            utils.showToast('Compte créé avec succès', 'success');
            
            // Connexion automatique
            const response = await apiService.login({
                username,
                master_password: password
            });
            
            this.setAuthData(response.access_token, response.user);
            this.showDashboard();
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    },

    async checkAuthStatus() {
        try {
            const user = await apiService.getCurrentUser();
            appState.currentUser = user;
            this.showDashboard();
        } catch (error) {
            this.logout();
        }
    },

    setAuthData(token, user) {
        appState.authToken = token;
        appState.currentUser = user;
        localStorage.setItem('sudosecure_token', token);
    },

    showDashboard() {
        document.getElementById('loginPage').style.display = 'none';
        document.getElementById('registerPage').style.display = 'none';
        document.getElementById('mainNav').style.display = 'block';
        document.getElementById('dashboard').style.display = 'block';
        
        document.getElementById('username').textContent = appState.currentUser.username;
        
        // Mettre à jour l'état 2FA
        this.update2FAStatus();
        
        // Charger les identifiants
        credentialManager.loadCredentials();
    },

    update2FAStatus() {
        const enabled = appState.currentUser.is_2fa_enabled;
        document.getElementById('2faEnabled').style.display = enabled ? 'block' : 'none';
        document.getElementById('2faDisabled').style.display = enabled ? 'none' : 'block';
    },

    logout() {
        appState.authToken = null;
        appState.currentUser = null;
        localStorage.removeItem('sudosecure_token');
        
        document.getElementById('mainNav').style.display = 'none';
        document.getElementById('dashboard').style.display = 'none';
        document.getElementById('loginPage').style.display = 'block';
        
        // Réinitialiser les formulaires
        document.getElementById('loginForm').reset();
        document.getElementById('registerForm').reset();
        document.getElementById('totpSection').style.display = 'none';
        
        utils.showToast('Déconnexion réussie', 'info');
    }
};

// Gestionnaire des identifiants
const credentialManager = {
    init() {
        this.bindEvents();
    },

    bindEvents() {
        // Bouton d'ajout
        document.getElementById('addCredentialBtn').addEventListener('click', () => {
            this.showCredentialModal();
        });
        
        // Recherche avec debounce
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('input', utils.debounce(() => {
            appState.searchQuery = searchInput.value;
            appState.currentPage = 1;
            this.loadCredentials();
        }, 300));
        
        // Modal d'identifiant
        document.getElementById('saveCredentialBtn').addEventListener('click', this.saveCredential.bind(this));
        document.getElementById('toggleCredentialPassword').addEventListener('click', this.toggleCredentialPassword);
        document.getElementById('generateForCredential').addEventListener('click', this.generatePasswordForCredential);
        
        // Modal de révélation de mot de passe
        document.getElementById('revealPasswordBtn').addEventListener('click', this.revealPassword.bind(this));
        document.getElementById('copyRevealedPassword').addEventListener('click', () => {
            const password = document.getElementById('revealedPasswordText').value;
            utils.copyToClipboard(password, document.getElementById('copyRevealedPassword'));
        });
    },

    async loadCredentials(page = 1) {
        try {
            const data = await apiService.getCredentials(page, appState.searchQuery);
            appState.credentials = data.results;
            appState.currentPage = page;
            appState.totalPages = Math.ceil(data.total / data.per_page);
            
            this.renderCredentials();
            this.renderPagination();
            
        } catch (error) {
            utils.showToast('Erreur lors du chargement des identifiants', 'error');
        }
    },

    renderCredentials() {
        const container = document.getElementById('credentialsList');
        
        if (appState.credentials.length === 0) {
            container.innerHTML = `
                <div class="text-center py-5">
                    <i class="bi bi-key display-4 text-muted"></i>
                    <p class="text-muted">Aucun identifiant trouvé</p>
                </div>
            `;
            return;
        }
        
        // Création sécurisée des éléments DOM (anti-XSS)
        container.innerHTML = '';
        
        appState.credentials.forEach(credential => {
            const card = document.createElement('div');
            card.className = 'card credential-card mb-3';
            
            const cardBody = document.createElement('div');
            cardBody.className = 'card-body';
            
            const row = document.createElement('div');
            row.className = 'row align-items-center';
            
            // Colonne info
            const colInfo = document.createElement('div');
            colInfo.className = 'col-md-8';
            
            // Titre (échappé)
            const title = document.createElement('h5');
            title.className = 'card-title mb-1';
            title.textContent = credential.title;
            colInfo.appendChild(title);
            
            // Username si présent (échappé)
            if (credential.username) {
                const userP = document.createElement('p');
                userP.className = 'card-text text-muted mb-1';
                userP.innerHTML = '<i class="bi bi-person"></i> ';
                const userSpan = document.createElement('span');
                userSpan.textContent = credential.username;
                userP.appendChild(userSpan);
                colInfo.appendChild(userP);
            }
            
            // Website URL si présent (validé et échappé)
            if (credential.website_url) {
                const validUrl = utils.validateUrl(credential.website_url);
                if (validUrl) {
                    const urlP = document.createElement('p');
                    urlP.className = 'card-text text-muted mb-1';
                    urlP.innerHTML = '<i class="bi bi-globe"></i> ';
                    const urlLink = document.createElement('a');
                    urlLink.href = validUrl;
                    urlLink.target = '_blank';
                    urlLink.rel = 'noopener noreferrer';
                    urlLink.textContent = validUrl;
                    urlP.appendChild(urlLink);
                    colInfo.appendChild(urlP);
                }
            }
            
            // Date de création
            const dateSmall = document.createElement('small');
            dateSmall.className = 'text-muted';
            dateSmall.textContent = `Créé le ${utils.formatDate(credential.created_at)}`;
            colInfo.appendChild(dateSmall);
            
            // Colonne actions
            const colActions = document.createElement('div');
            colActions.className = 'col-md-4 text-end';
            
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'credential-actions';
            
            // Bouton Voir
            const btnView = document.createElement('button');
            btnView.className = 'btn btn-outline-primary btn-sm';
            btnView.innerHTML = '<i class="bi bi-eye"></i> Voir';
            btnView.onclick = () => credentialManager.showRevealModal(credential.id);
            actionsDiv.appendChild(btnView);
            actionsDiv.appendChild(document.createTextNode(' '));
            
            // Bouton Modifier
            const btnEdit = document.createElement('button');
            btnEdit.className = 'btn btn-outline-secondary btn-sm';
            btnEdit.innerHTML = '<i class="bi bi-pencil"></i>';
            btnEdit.onclick = () => credentialManager.editCredential(credential.id);
            actionsDiv.appendChild(btnEdit);
            actionsDiv.appendChild(document.createTextNode(' '));
            
            // Bouton Supprimer
            const btnDelete = document.createElement('button');
            btnDelete.className = 'btn btn-outline-danger btn-sm';
            btnDelete.innerHTML = '<i class="bi bi-trash"></i>';
            btnDelete.onclick = () => credentialManager.deleteCredential(credential.id);
            actionsDiv.appendChild(btnDelete);
            
            colActions.appendChild(actionsDiv);
            
            // Assemblage
            row.appendChild(colInfo);
            row.appendChild(colActions);
            cardBody.appendChild(row);
            card.appendChild(cardBody);
            container.appendChild(card);
        });
    },

    renderPagination() {
        const container = document.getElementById('paginationList');
        const pagination = document.getElementById('pagination');
        
        if (appState.totalPages <= 1) {
            pagination.style.display = 'none';
            return;
        }
        
        pagination.style.display = 'block';
        
        let paginationHtml = '';
        
        // Bouton précédent
        paginationHtml += `
            <li class="page-item ${appState.currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="credentialManager.loadCredentials(${appState.currentPage - 1})">&laquo;</a>
            </li>
        `;
        
        // Pages
        for (let i = 1; i <= appState.totalPages; i++) {
            if (i === 1 || i === appState.totalPages || (i >= appState.currentPage - 2 && i <= appState.currentPage + 2)) {
                paginationHtml += `
                    <li class="page-item ${i === appState.currentPage ? 'active' : ''}">
                        <a class="page-link" href="#" onclick="credentialManager.loadCredentials(${i})">${i}</a>
                    </li>
                `;
            } else if (i === appState.currentPage - 3 || i === appState.currentPage + 3) {
                paginationHtml += '<li class="page-item disabled"><span class="page-link">...</span></li>';
            }
        }
        
        // Bouton suivant
        paginationHtml += `
            <li class="page-item ${appState.currentPage === appState.totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="credentialManager.loadCredentials(${appState.currentPage + 1})">&raquo;</a>
            </li>
        `;
        
        container.innerHTML = paginationHtml;
    },

    showCredentialModal(credentialId = null) {
        appState.currentCredentialId = credentialId;
        
        if (credentialId) {
            document.getElementById('credentialModalTitle').textContent = 'Modifier l\'identifiant';
            this.loadCredentialForEdit(credentialId);
        } else {
            document.getElementById('credentialModalTitle').textContent = 'Ajouter un identifiant';
            document.getElementById('credentialForm').reset();
            document.getElementById('credentialId').value = '';
        }
        
        const modal = new bootstrap.Modal(document.getElementById('credentialModal'));
        modal.show();
    },

    async loadCredentialForEdit(id) {
        try {
            const credential = await apiService.getCredential(id);
            
            document.getElementById('credentialId').value = credential.id;
            document.getElementById('credentialTitle').value = credential.title;
            document.getElementById('credentialUrl').value = credential.website_url || '';
            document.getElementById('credentialUsername').value = credential.username || '';
            document.getElementById('credentialNotes').value = credential.notes || '';
            // Le mot de passe ne peut pas être pré-rempli pour des raisons de sécurité
            
        } catch (error) {
            utils.showToast('Erreur lors du chargement de l\'identifiant', 'error');
        }
    },

    async saveCredential() {
        const idEl = document.getElementById('credentialId');
        const titleEl = document.getElementById('credentialTitle');
        const urlEl = document.getElementById('credentialUrl');
        const userEl = document.getElementById('credentialUsername');
        const passEl = document.getElementById('credentialPassword');
        const notesEl = document.getElementById('credentialNotes');

        if (!idEl || !titleEl || !urlEl || !userEl || !passEl || !notesEl) {
            utils.showToast("Formulaire d'identifiant introuvable dans la page", 'error');
            return;
        }

        const credentialId = idEl.value;
        const title = titleEl.value;
        const website_url = urlEl.value;
        const username = userEl.value;
        const password = passEl.value;
        const notes = notesEl.value;
        // Le mot de passe maître n'est plus requis à la création/mise à jour
        if (!title.trim()) {
            utils.showToast('Titre requis', 'error');
            return;
        }
        
        try {
            const credentialData = {
                title: title.trim(),
                website_url: website_url || null,
                username: username || null,
                notes: notes || null
            };
            
            if (credentialId) {
                // Mise à jour
                if (password) credentialData.password = password;
                await apiService.updateCredential(credentialId, credentialData);
                utils.showToast('Identifiant mis à jour', 'success');
            } else {
                // Création
                if (!password) {
                    utils.showToast('Mot de passe requis pour un nouvel identifiant', 'error');
                    return;
                }
                credentialData.password = password;
                await apiService.createCredential(credentialData);
                utils.showToast('Identifiant créé', 'success');
            }
            
            // Fermer le modal et recharger
            bootstrap.Modal.getInstance(document.getElementById('credentialModal')).hide();
            this.loadCredentials(appState.currentPage);
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    },

    editCredential(id) {
        this.showCredentialModal(id);
    },

    async deleteCredential(id) {
        if (!confirm('Êtes-vous sûr de vouloir supprimer cet identifiant ?')) {
            return;
        }
        
        try {
            await apiService.deleteCredential(id);
            utils.showToast('Identifiant supprimé', 'success');
            this.loadCredentials(appState.currentPage);
        } catch (error) {
            utils.showToast('Erreur lors de la suppression', 'error');
        }
    },

    showRevealModal(id) {
        appState.currentCredentialId = id;
        document.getElementById('revealPasswordForm').reset();
        document.getElementById('revealedPassword').style.display = 'none';
        
        const modal = new bootstrap.Modal(document.getElementById('revealPasswordModal'));
        modal.show();
    },

    async revealPassword() {
        const masterPassword = document.getElementById('masterPasswordReveal').value;
        try {
            const data = await apiService.revealPassword(appState.currentCredentialId, masterPassword || null);
            
            document.getElementById('revealedPasswordText').value = data.password;
            document.getElementById('revealedPassword').style.display = 'block';
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    },

    toggleCredentialPassword() {
        const input = document.getElementById('credentialPassword');
        const icon = this.querySelector('i');
        
        if (input && input.type === 'password') {
            input.type = 'text';
            icon.className = 'bi bi-eye-slash';
        } else {
            if (input) input.type = 'password';
            if (icon) icon.className = 'bi bi-eye';
        }
    },

    async generatePasswordForCredential() {
        try {
            const options = {
                length: 16,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_symbols: true
            };
            
            const data = await apiService.generatePassword(options);
            document.getElementById('credentialPassword').value = data.password;
            
            utils.showToast('Mot de passe généré', 'success');
            
        } catch (error) {
            utils.showToast('Erreur lors de la génération', 'error');
        }
    }
};

// Gestionnaire du générateur de mots de passe
const passwordGenerator = {
    init() {
        this.bindEvents();
    },

    bindEvents() {
        const lengthSlider = document.getElementById('passwordLength');
        const lengthValue = document.getElementById('lengthValue');
        
        lengthSlider.addEventListener('input', () => {
            lengthValue.textContent = lengthSlider.value;
        });
        
        document.getElementById('generatePasswordBtn').addEventListener('click', this.generatePassword.bind(this));
        document.getElementById('copyPasswordBtn').addEventListener('click', this.copyGeneratedPassword.bind(this));
    },

    async generatePassword() {
        const options = {
            length: parseInt(document.getElementById('passwordLength').value),
            include_uppercase: document.getElementById('includeUppercase').checked,
            include_lowercase: document.getElementById('includeLowercase').checked,
            include_numbers: document.getElementById('includeNumbers').checked,
            include_symbols: document.getElementById('includeSymbols').checked
        };
        
        // Vérifier qu'au moins une option est cochée
        if (!Object.values(options).slice(1).some(Boolean)) {
            utils.showToast('Au moins un type de caractère doit être sélectionné', 'error');
            return;
        }
        
        try {
            const data = await apiService.generatePassword(options);
            
            document.getElementById('generatedPassword').value = data.password;
            
            const strengthBar = document.getElementById('strengthBar');
            const strengthText = document.getElementById('strengthText');
            
            utils.updatePasswordStrength(data.password, strengthBar, strengthText);
            
        } catch (error) {
            utils.showToast('Erreur lors de la génération', 'error');
        }
    },

    copyGeneratedPassword() {
        const password = document.getElementById('generatedPassword').value;
        utils.copyToClipboard(password, document.getElementById('copyPasswordBtn'));
    }
};

// Gestionnaire de la sécurité (2FA)
const securityManager = {
    init() {
        this.bindEvents();
    },

    bindEvents() {
        document.getElementById('enable2faBtn').addEventListener('click', this.setup2FA.bind(this));
        document.getElementById('disable2faBtn').addEventListener('click', this.disable2FA.bind(this));
        document.getElementById('verify2faBtn').addEventListener('click', this.verify2FA.bind(this));
        
        // Copie des éléments 2FA
        document.getElementById('copySecretKey').addEventListener('click', () => {
            const secret = document.getElementById('secretKey').value;
            utils.copyToClipboard(secret, document.getElementById('copySecretKey'));
        });
        
        document.getElementById('copyBackupCodes').addEventListener('click', () => {
            const codes = document.getElementById('backupCodes').textContent;
            utils.copyToClipboard(codes, document.getElementById('copyBackupCodes'));
        });
    },

    async setup2FA() {
        try {
            const data = await apiService.setup2FA();
            
            document.getElementById('qrCodeImage').src = data.qr_code_url;
            document.getElementById('secretKey').value = data.secret;
            document.getElementById('backupCodes').textContent = data.backup_codes.join('\n');
            
            const modal = new bootstrap.Modal(document.getElementById('setup2faModal'));
            modal.show();
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    },

    async verify2FA() {
        const code = document.getElementById('verify2faCode').value;
        
        if (!code || code.length !== 6) {
            utils.showToast('Code de vérification invalide', 'error');
            return;
        }
        
        try {
            await apiService.verify2FA(code);
            
            utils.showToast('2FA activé avec succès', 'success');
            
            // Mettre à jour l'état utilisateur
            appState.currentUser.is_2fa_enabled = true;
            authManager.update2FAStatus();
            
            bootstrap.Modal.getInstance(document.getElementById('setup2faModal')).hide();
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    },

    async disable2FA() {
        if (!confirm('Êtes-vous sûr de vouloir désactiver la 2FA ?')) {
            return;
        }
        
        try {
            await apiService.disable2FA();
            
            utils.showToast('2FA désactivé', 'success');
            
            // Mettre à jour l'état utilisateur
            appState.currentUser.is_2fa_enabled = false;
            authManager.update2FAStatus();
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    }
};

// Navigation entre les sections
const navigationManager = {
    init() {
        document.getElementById('credentialsTab').addEventListener('click', (e) => {
            e.preventDefault();
            utils.showSection('credentialsSection');
        });
        
        document.getElementById('generatorTab').addEventListener('click', (e) => {
            e.preventDefault();
            utils.showSection('generatorSection');
        });
        
        document.getElementById('securityTab').addEventListener('click', (e) => {
            e.preventDefault();
            utils.showSection('securitySection');
        });
    }
};

// Initialisation de l'application
document.addEventListener('DOMContentLoaded', function() {
    authManager.init();
    credentialManager.init();
    passwordGenerator.init();
    securityManager.init();
    navigationManager.init();
    
    console.log('SudoSecure initialisé');
});

// Gestion des erreurs globales
window.addEventListener('error', function(e) {
    console.error('Erreur JavaScript:', e.error);
    utils.showToast('Une erreur inattendue s\'est produite', 'error');
});

// Gestion des erreurs de promesses non capturées
window.addEventListener('unhandledrejection', function(e) {
    console.error('Promesse rejetée:', e.reason);
    utils.showToast('Erreur de connexion', 'error');
});

// Export pour utilisation globale (si nécessaire)
window.SudoSecure = {
    utils,
    authManager,
    credentialManager,
    passwordGenerator,
    securityManager
};