# Installation

## 📥 Téléchargement

```bash
git clone https://github.com/fred-selest/microsoft-active-directory.git
cd microsoft-active-directory
```

Ou téléchargez le ZIP: https://github.com/fred-selest/microsoft-active-directory/archive/refs/heads/main.zip

---

## 🪟 Windows

**Installation automatique:**
```cmd
setup_windows.bat
```

**Lancement:**
```cmd
run.bat
```

**Si erreur MD4 (Python 3.12+):**
```cmd
run_legacy.bat
```

---

## 🐧 Linux / Ubuntu

**Installation automatique:**
```bash
chmod +x setup_linux.sh
./setup_linux.sh
```

**Lancement:**
```bash
./run.sh
```

---

## 📚 Autres ressources

- **Installation avancée Linux:** `INSTALL_UBUNTU.md`
- **Correction MD4 Python 3.12+:** `README_MD4.md`
- **Installation interactive:** `python3 install.py` (Windows/Linux)

---

## 🌐 Accès

Une fois lancé, ouvrez votre navigateur:

- **Local:** http://localhost:5000
- **Réseau:** http://VOTRE_IP:5000

---

## ⚠️ Problèmes courants

### Windows
- **Python non trouvé:** Téléchargez depuis https://www.python.org et cochez "Add to PATH"
- **Erreur MD4:** Utilisez `run_legacy.bat`

### Linux
- **python3-venv introuvable:** `sudo apt install python3-venv`
- **Permission refusée:** `chmod +x setup_linux.sh run.sh`

---

## 🔧 Configuration

Modifiez le fichier `.env`:
```ini
SECRET_KEY=votre-cle-secrete-aleatoire
HOST=0.0.0.0
PORT=5000
```

**⚠️ IMPORTANT:** Changez `SECRET_KEY` en production!
