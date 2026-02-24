# Installation

## 📥 Téléchargement

```bash
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory
```

Ou téléchargez le ZIP: https://github.com/fred-selest/microsoft-active-directory/archive/refs/heads/main.zip

---

## 🪟 Windows

**Lancement (installation automatique incluse):**
```cmd
run.bat
```

- Installe Python 3 automatiquement s'il est absent
- Crée le venv et installe les dépendances
- Génère le fichier `.env` au premier lancement
- Active le support MD4/NTLM automatiquement pour Python 3.12+

---

## 🐧 Linux / macOS

**Lancement (installation automatique incluse):**
```bash
./run.sh
```

- Propose d'installer Python 3 automatiquement s'il est absent (apt/dnf/pacman/brew)
- Crée le venv et installe les dépendances
- Génère le fichier `.env` au premier lancement

---

## 📚 Autres ressources

- **Installation avancée Linux:** `INSTALL_UBUNTU.md`
- **Correction MD4 Python 3.12+:** `README_MD4.md` (géré automatiquement par `run.bat`)
- **Installation interactive:** `python3 install.py` (Windows/Linux)

---

## 🌐 Accès

Une fois lancé, ouvrez votre navigateur:

- **Local:** http://localhost:5000
- **Réseau:** http://VOTRE_IP:5000

---

## ⚠️ Problèmes courants

### Windows
- **Python non installé:** `run.bat` propose de l'installer automatiquement
- **Erreur MD4:** Déjà gérée automatiquement par `run.bat` pour Python 3.12+

### Linux
- **Python absent:** `run.sh` propose de l'installer via le gestionnaire de paquets
- **Permission refusée:** `chmod +x run.sh`

---

## 🔧 Configuration

Le fichier `.env` est généré automatiquement au premier lancement.
Pour personnaliser, modifiez `.env` :
```ini
AD_SERVER=votre-serveur-ad
AD_BASE_DN=DC=exemple,DC=com
SECRET_KEY=votre-cle-secrete
```
