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
            throw error;
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
        
        const credentialsHtml = appState.credentials.map(credential => `
            <div class="card credential-card mb-3">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <h5 class="card-title mb-1">${credential.title}</h5>
                            ${credential.username ? `<p class="card-text text-muted mb-1"><i class="bi bi-person"></i> ${credential.username}</p>` : ''}
                            ${credential.website_url ? `<p class="card-text text-muted mb-1"><i class="bi bi-globe"></i> <a href="${credential.website_url}" target="_blank">${credential.website_url}</a></p>` : ''}
                            <small class="text-muted">Créé le ${utils.formatDate(credential.created_at)}</small>
                        </div>
                        <div class="col-md-4 text-end">
                            <div class="credential-actions">
                                <button class="btn btn-outline-primary btn-sm" onclick="credentialManager.showRevealModal(${credential.id})">
                                    <i class="bi bi-eye"></i> Voir
                                </button>
                                <button class="btn btn-outline-secondary btn-sm" onclick="credentialManager.editCredential(${credential.id})">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn btn-outline-danger btn-sm" onclick="credentialManager.deleteCredential(${credential.id})">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = credentialsHtml;
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
        const credentialId = document.getElementById('credentialId').value;
        const title = document.getElementById('credentialTitle').value;
        const website_url = document.getElementById('credentialUrl').value;
        const username = document.getElementById('credentialUsername').value;
        const password = document.getElementById('credentialPassword').value;
        const notes = document.getElementById('credentialNotes').value;
        const master_password = document.getElementById('masterPasswordModal').value;
        
        if (!title.trim() || !master_password) {
            utils.showToast('Titre et mot de passe maître requis', 'error');
            return;
        }
        
        try {
            const credentialData = {
                title: title.trim(),
                website_url: website_url || null,
                username: username || null,
                notes: notes || null,
                master_password
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
        
        if (!masterPassword) {
            utils.showToast('Mot de passe maître requis', 'error');
            return;
        }
        
        try {
            const data = await apiService.revealPassword(appState.currentCredentialId, masterPassword);
            
            document.getElementById('revealedPasswordText').value = data.password;
            document.getElementById('revealedPassword').style.display = 'block';
            
        } catch (error) {
            utils.showToast(error.message, 'error');
        }
    },

    toggleCredentialPassword() {
        const input = document.getElementById('credentialPassword');
        const icon = this.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.className = 'bi bi-eye-slash';
        } else {
            input.type = 'password';
            icon.className = 'bi bi-eye';
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
        
        // Génération automatique d'un mot de passe au chargement
        this.generatePassword();
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