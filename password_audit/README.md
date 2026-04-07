# 🔐 password_audit — Audit des Mots de Passe

**Répertoire :** `password_audit/`

---

## 🎯 Rôle

Le répertoire `password_audit/` contient le **moteur d'audit des mots de passe** Active Directory. Il analyse la force des mots de passe des utilisateurs et génère des rapports détaillés.

**Fonctionnalités :**
- Analyse de la complexité des mots de passe
- Détection des mots de passe faibles
- Génération de rapports PDF/Excel
- Score de sécurité 0-100
- Vérification contre les listes noires

---

## 📁 Structure

```
password_audit/
├── __init__.py           # Package password_audit
├── protocol.py           # Protocole d'audit (interface)
├── constants.py          # Constantes et configurations
├── checks.py             # Vérifications de complexité
├── analyzer.py           # Analyseur principal
├── runner.py             # Exécuteur d'audit
├── report.py             # Génération de rapports
├── export.py             # Export des résultats
└── admin.py              # Interface d'administration
```

---

## 🔑 Modules

### 1. `protocol.py` — Interface

Définit l'interface pour les vérifications de mots de passe.

```python
from typing import Protocol, List

class PasswordCheck(Protocol):
    """Interface pour une vérification de mot de passe."""
    
    def check(self, password: str) -> bool:
        """Vérifie le mot de passe. Retourne True si valide."""
        ...
    
    def get_message(self) -> str:
        """Retourne le message d'erreur si échec."""
        ...
```

---

### 2. `constants.py` — Constantes

Définit les configurations globales.

```python
# Seuils de complexité
COMPLEXITY_LOW = 20
COMPLEXITY_MEDIUM = 50
COMPLEXITY_HIGH = 80

# Longueur minimale
MIN_PASSWORD_LENGTH = 8

# Listes noires
COMMON_PASSWORDS_FILE = 'password_audit/data/common_passwords.txt'

# Caractères ambigus
AMBIGUOUS_CHARS = 'l1I0O'

# Messages d'erreur
ERROR_MESSAGES = {
    'too_short': 'Le mot de passe est trop court',
    'no_uppercase': 'Aucune lettre majuscule',
    'no_lowercase': 'Aucune lettre minuscule',
    'no_digit': 'Aucun chiffre',
    'no_special': 'Aucun caractère spécial',
    'common_password': 'Mot de passe trop courant',
    ...
}
```

---

### 3. `checks.py` — Vérifications

Implémente toutes les vérifications de complexité.

```python
from .protocol import PasswordCheck

class LengthCheck:
    """Vérifie la longueur minimale."""
    
    def __init__(self, min_length: int = 8):
        self.min_length = min_length
    
    def check(self, password: str) -> bool:
        return len(password) >= self.min_length
    
    def get_message(self) -> str:
        return f'Longueur minimale : {self.min_length} caractères'


class UppercaseCheck:
    """Vérifie la présence d'au moins une majuscule."""
    
    def check(self, password: str) -> bool:
        return any(c.isupper() for c in password)
    
    def get_message(self) -> str:
        return 'Au moins une lettre majuscule requise'


class DigitCheck:
    """Vérifie la présence d'au moins un chiffre."""
    
    def check(self, password: str) -> bool:
        return any(c.isdigit() for c in password)
    
    def get_message(self) -> str:
        return 'Au moins un chiffre requis'


class SpecialCharCheck:
    """Vérifie la présence d'au moins un caractère spécial."""
    
    def check(self, password: str) -> bool:
        special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        return any(c in special_chars for c in password)
    
    def get_message(self) -> str:
        return 'Au moins un caractère spécial requis'


class CommonPasswordCheck:
    """Vérifie que le mot de passe n'est pas dans la liste noire."""
    
    def __init__(self, common_passwords: set):
        self.common_passwords = common_passwords
    
    def check(self, password: str) -> bool:
        return password.lower() not in self.common_passwords
    
    def get_message(self) -> str:
        return 'Mot de passe trop courant (liste noire)'
```

---

### 4. `analyzer.py` — Analyseur Principal

Orchestre toutes les vérifications et calcule le score.

```python
from .checks import (
    LengthCheck, UppercaseCheck, LowercaseCheck,
    DigitCheck, SpecialCharCheck, CommonPasswordCheck
)

class PasswordAnalyzer:
    """Analyseur de mots de passe."""
    
    def __init__(self):
        self.checks = [
            LengthCheck(min_length=8),
            UppercaseCheck(),
            LowercaseCheck(),
            DigitCheck(),
            SpecialCharCheck(),
            CommonPasswordCheck(self._load_common_passwords())
        ]
    
    def analyze(self, password: str) -> dict:
        """
        Analyse un mot de passe.
        
        Retourne :
        {
            'valid': bool,          # Toutes les vérifications sont OK
            'score': int,           # Score 0-100
            'checks': [             # Détails des vérifications
                {'name': 'length', 'passed': True},
                {'name': 'uppercase', 'passed': False},
                ...
            ],
            'errors': [             # Messages d'erreur
                'Aucune lettre majuscule',
                ...
            ],
            'complexity': str       # 'low', 'medium', 'high'
        }
        """
        results = []
        errors = []
        passed_count = 0
        
        for check in self.checks:
            passed = check.check(password)
            results.append({
                'name': check.__class__.__name__,
                'passed': passed
            })
            
            if passed:
                passed_count += 1
            else:
                errors.append(check.get_message())
        
        score = int((passed_count / len(self.checks)) * 100)
        
        return {
            'valid': len(errors) == 0,
            'score': score,
            'checks': results,
            'errors': errors,
            'complexity': self._get_complexity_label(score)
        }
    
    def _get_complexity_label(self, score: int) -> str:
        if score < 30:
            return 'low'
        elif score < 70:
            return 'medium'
        else:
            return 'high'
    
    def _load_common_passwords(self) -> set:
        """Charge la liste des mots de passe courants."""
        # Charge depuis password_audit/data/common_passwords.txt
        ...
```

---

### 5. `runner.py` — Exécuteur d'Audit

Exécute l'audit sur tous les utilisateurs AD.

```python
from ldap3 import SUBTREE
from .analyzer import PasswordAnalyzer

class AuditRunner:
    """Exécuteur d'audit des mots de passe."""
    
    def __init__(self, ldap_connection):
        self.conn = ldap_connection
        self.analyzer = PasswordAnalyzer()
    
    def run_audit(self, base_dn: str) -> list:
        """
        Exécute l'audit sur tous les utilisateurs.
        
        Retourne une liste de résultats :
        [
            {
                'username': 'john.doe',
                'dn': 'CN=John Doe,OU=Users...',
                'password_hint': 'P***d',  # Indice (ne révèle pas le MDP)
                'score': 75,
                'complexity': 'high',
                'errors': []
            },
            ...
        ]
        """
        results = []
        
        # Rechercher tous les utilisateurs
        self.conn.search(
            base_dn,
            '(objectClass=user)',
            SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName', 'pwdLastSet']
        )
        
        for entry in self.conn.entries:
            username = str(entry.sAMAccountName)
            
            # Note: On ne peut pas lire les mots de passe AD directement
            # On utilise des heuristiques basées sur :
            # - Date de dernière modification
            # - Historique des mots de passe
            # - Tests de connexion avec mots de passe courants
            
            result = self._analyze_user_heuristic(entry)
            results.append(result)
        
        return results
    
    def _analyze_user_heuristic(self, entry) -> dict:
        """Analyse heuristique (sans accès au mot de passe)."""
        # Cette méthode utilise des indices pour estimer la force
        # - pwdLastSet ancien = mot de passe potentiellement faible
        # - Nom d'utilisateur dans le MDP = faible
        # - etc.
        ...
```

---

### 6. `report.py` — Génération de Rapports

Génère des rapports PDF et HTML.

```python
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

class ReportGenerator:
    """Générateur de rapports d'audit."""
    
    def __init__(self, audit_results: list):
        self.results = audit_results
    
    def generate_pdf(self, output_path: str):
        """Génère un rapport PDF."""
        c = canvas.Canvas(output_path, pagesize=A4)
        
        # Titre
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 800, "Rapport d'Audit des Mots de Passe")
        
        # Statistiques
        c.setFont("Helvetica", 12)
        c.drawString(50, 750, f"Total utilisateurs: {len(self.results)}")
        
        weak_count = sum(1 for r in self.results if r['score'] < 50)
        c.drawString(50, 730, f"Mots de passe faibles: {weak_count}")
        
        # Tableau des résultats
        y = 700
        c.drawString(50, y, "Utilisateur")
        c.drawString(200, y, "Score")
        c.drawString(300, y, "Complexité")
        c.drawString(400, y, "Erreurs")
        
        y -= 20
        for result in self.results:
            c.drawString(50, y, result['username'])
            c.drawString(200, y, str(result['score']))
            c.drawString(300, y, result['complexity'])
            c.drawString(400, y, ', '.join(result['errors'][:2]))
            y -= 20
            
            if y < 50:  # Nouvelle page
                c.showPage()
                y = 800
        
        c.save()
    
    def generate_html(self) -> str:
        """Génère un rapport HTML."""
        html = """
        <html>
        <head><title>Rapport d'Audit MDP</title></head>
        <body>
            <h1>Rapport d'Audit des Mots de Passe</h1>
            <table>
                <tr>
                    <th>Utilisateur</th>
                    <th>Score</th>
                    <th>Complexité</th>
                    <th>Erreurs</th>
                </tr>
        """
        
        for result in self.results:
            color = 'green' if result['score'] >= 70 else 'orange' if result['score'] >= 50 else 'red'
            html += f"""
                <tr>
                    <td>{result['username']}</td>
                    <td style="color: {color}">{result['score']}</td>
                    <td>{result['complexity']}</td>
                    <td>{', '.join(result['errors'])}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        return html
```

---

### 7. `export.py` — Export des Résultats

Exporte les résultats en CSV et Excel.

```python
import csv
from openpyxl import Workbook

class Exporter:
    """Export des résultats d'audit."""
    
    def __init__(self, audit_results: list):
        self.results = audit_results
    
    def export_csv(self, output_path: str):
        """Export en CSV."""
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Username', 'Score', 'Complexity', 'Errors'])
            
            for result in self.results:
                writer.writerow([
                    result['username'],
                    result['score'],
                    result['complexity'],
                    '; '.join(result['errors'])
                ])
    
    def export_excel(self, output_path: str):
        """Export en Excel."""
        wb = Workbook()
        ws = wb.active
        ws.title = "Audit MDP"
        
        # En-têtes
        ws.append(['Username', 'Score', 'Complexity', 'Errors'])
        
        # Données
        for result in self.results:
            ws.append([
                result['username'],
                result['score'],
                result['complexity'],
                '; '.join(result['errors'])
            ])
        
        # Formatage conditionnel
        for row in range(2, len(self.results) + 2):
            score_cell = ws[f'B{row}']
            if score_cell.value < 50:
                score_cell.font = Font(color='FF0000')  # Rouge
            elif score_cell.value < 70:
                score_cell.font = Font(color='FFA500')  # Orange
            else:
                score_cell.font = Font(color='008000')  # Vert
        
        wb.save(output_path)
```

---

### 8. `admin.py` — Interface d'Administration

Fournit les routes pour l'interface web.

```python
from flask import Blueprint, render_template, request, send_file
from .runner import AuditRunner
from .report import ReportGenerator
from .export import Exporter

admin_bp = Blueprint('password_audit_admin', __name__)

@admin_bp.route('/password-audit')
def password_audit_page():
    """Page d'audit des mots de passe."""
    return render_template('password_audit.html')

@admin_bp.route('/password-audit/run', methods=['POST'])
def run_audit():
    """Exécute l'audit."""
    runner = AuditRunner(get_ad_connection())
    results = runner.run_audit(session['ad_base_dn'])
    
    # Stocker les résultats en session
    session['audit_results'] = results
    
    return redirect(url_for('password_audit_results'))

@admin_bp.route('/password-audit/results')
def password_audit_results():
    """Affiche les résultats."""
    results = session.get('audit_results', [])
    return render_template('password_auditor_report.html', results=results)

@admin_bp.route('/password-audit/export/csv')
def export_csv():
    """Export CSV."""
    results = session.get('audit_results', [])
    exporter = Exporter(results)
    
    output_path = 'data/audit_mdp.csv'
    exporter.export_csv(output_path)
    
    return send_file(output_path, as_attachment=True)

@admin_bp.route('/password-audit/export/pdf')
def export_pdf():
    """Export PDF."""
    results = session.get('audit_results', [])
    generator = ReportGenerator(results)
    
    output_path = 'data/audit_mdp.pdf'
    generator.generate_pdf(output_path)
    
    return send_file(output_path, as_attachment=True)
```

---

## 📊 Métriques d'Audit

### Score de Complexité

| Score | Niveau | Couleur | Action |
|-------|--------|---------|--------|
| 0-29 | Faible | Rouge | Réinitialisation requise |
| 30-69 | Moyen | Orange | Recommandation |
| 70-100 | Fort | Vert | Conforme |

### Vérifications Effectuées

| Vérification | Poids | Description |
|--------------|-------|-------------|
| Longueur ≥ 8 | 20% | Minimum 8 caractères |
| Majuscules | 15% | Au moins une lettre majuscule |
| Minuscules | 15% | Au moins une lettre minuscule |
| Chiffres | 15% | Au moins un chiffre |
| Caractères spéciaux | 15% | Au moins un caractère spécial |
| Pas dans liste noire | 20% | Pas un mot de passe courant |

---

## 🔒 Sécurité

### Limites d'Active Directory

**Important :** AD ne permet **pas** de lire les mots de passe en clair.

**Solutions alternatives :**
1. **Audit heuristique** — Basé sur les métadonnées (date, historique)
2. **Test de connexion** — Tester avec des mots de passe courants
3. **Analyse post-réinitialisation** — Analyser quand l'utilisateur change son MDP

---

### Protection des Résultats

Les résultats d'audit sont **sensibles** :

- **Permissions requises :** `tools:password_audit`
- **Stockage :** Fichiers dans `data/audit_history/` (non versionnés)
- **Accès :** Réservé aux administrateurs

---

## 📈 Utilisation

### Via l'Interface Web

1. Naviguer vers `/tools/password-audit`
2. Cliquer sur "Lancer l'audit"
3. Consulter les résultats
4. Exporter en PDF/CSV/Excel

---

### Via l'API

```bash
# Lancer l'audit
curl -X POST http://localhost:5000/api/password-audit/run \
    -H "Cookie: session=..."

# Récupérer les résultats
curl http://localhost:5000/api/password-audit/results \
    -H "Cookie: session=..."
```

---

### En Ligne de Commande

```python
from password_audit import AuditRunner, ReportGenerator

# Initialiser
conn = get_ad_connection()
runner = AuditRunner(conn)

# Exécuter
results = runner.run_audit('DC=corp,DC=local')

# Générer rapport
generator = ReportGenerator(results)
generator.generate_pdf('rapport_audit.pdf')
```

---

## 🧪 Tests

```bash
# Tests du module password_audit
pytest tests/test_password_audit.py
pytest tests/test_password_policy.py
```

---

## 📝 Bonnes Pratiques

### 1. Planifier l'Audit

Exécuter l'audit **mensuellement** pour suivre l'évolution.

### 2. Actions Correctives

Pour les mots de passe faibles :
- Envoyer un email de notification
- Forcer la réinitialisation au prochain login
- Former les utilisateurs

### 3. Politique de Mot de Passe

Recommandations :
- **Longueur minimale :** 12 caractères
- **Complexité :** Haute (maj, min, chiffres, spéciaux)
- **Historique :** 10 mots de passe mémorisés
- **Durée de vie :** 90 jours maximum

---

**Version :** 1.35.0  
**Mainteneur :** Équipe AD Web Interface
