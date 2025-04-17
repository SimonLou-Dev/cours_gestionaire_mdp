# 🔐 Password Vault
## Gestionnaire de Mots de Passe Sécurisé
### B3 ESGI S2 2024- Scripting Python - Bidet Simon

**Password Vault** est une application web **sécurisée** de gestion de mots de passe, permettant aux utilisateurs de **stocker**, **générer** et **partager** des mots de passe de manière **sécurisée**. Elle inclut une interface web fluide, une authentification forte (TOTP), et une architecture orientée sécurité.

# ✨ Fonctionnalités

- 🔑 Générateur de mots de passe robustes
- 📋 Tableau de bord pour consulter et gérer ses mots de passe
- 🔒 Chiffrement AES des données sensibles (mots de passe, identifiants, emails)
- 🔗 Partage sécurisé via lien temporaire (maximum 24h)
- 🔐 Authentification TOTP (obligatoire pour les comptes utilisateurs)
- 🌐 Interface utilisateur en FastAPI + Jinja2 avec TailwindCSS

# 🧱 Stack Technique

- **Backend :** FastAPI
- **Frontend :** Jinja2 + TailwindCSS + Lucide Icons
- **Base de données :** SQLite
- **ORM :** SQLAlchemy
- **Authentification :** TOTP (Two-Factor Authentication)
- **Chiffrement :** AES avec clés dérivées utilisateur


# 🚀 Lancer l'application

Cloner le dépôt :

```bash
git clone https://github.com/SimonLou-Dev/cours_gestionaire_mdp
cd password-vault
```

Créer l’environnement virtuel :

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux
```

Installer les dépendances :

```bash
pip install -r requirements.txt
```


Démarrer l’application :

```bash
uvicorn app.main:app --reload
```

Accéder à l’interface :
http://localhost:8000



# 🔒 Authentification TOTP

L’authentification à deux facteurs est activable pour les comptes utilisateurs. Une fois activée :
- Un QR Code est généré à scanner avec une app (Google Authenticator, Authy, etc).
- À chaque connexion, l’utilisateur doit fournir un code temporaire.

# 📦 Structure du projet

```
app/
├── main.py                 # Entrée FastAPI
├── models/                 # SQLAlchemy ORM
├── templates/              # Fichiers Jinja2
├── static/                 # CSS/JS
├── routes/                 # Endpoints FastAPI
├── services/               # Chiffrement, partage, TOTP
```
