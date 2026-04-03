"""
Analyse CSS unused rules - AD Web Interface
Compare les règles CSS avec les templates HTML
"""
import re
from pathlib import Path

# Lire le CSS
css_file = Path('static/css/styles.css')
css_content = css_file.read_text(encoding='utf-8')

# Lire tous les templates
templates_dir = Path('templates')
html_content = ''
for tpl in templates_dir.glob('*.html'):
    html_content += tpl.read_text(encoding='utf-8') + '\n'

# Extraire tous les sélecteurs CSS
selectors = re.findall(r'^([.#\[][\w\-]+)', css_content, re.MULTILINE)
selectors = list(set(selectors))  # Unique

print(f"\n{'='*70}")
print(f" ANALYSE CSS UNUSED - {len(selectors)} sélecteurs")
print(f"{'='*70}\n")

# Vérifier quels sélecteurs sont utilisés
unused = []
used = []

for selector in selectors:
    # Nettoyer le sélecteur
    clean = selector.strip('.#[]')
    
    # Chercher dans le HTML
    if clean in html_content or selector in html_content:
        used.append(selector)
    else:
        # Vérifier variantes
        found = False
        for variant in [f'class="{clean}"', f"id=\"{clean}\"", clean]:
            if variant in html_content:
                found = True
                break
        if found:
            used.append(selector)
        else:
            unused.append(selector)

print(f"✅ Utilisés: {len(used)}")
print(f"❌ Non utilisés: {len(unused)}")

if unused:
    print(f"\n{'='*70}")
    print(f" SÉLECTEURS NON UTILISÉS (à supprimer)")
    print(f"{'='*70}\n")
    
    for sel in sorted(unused)[:50]:  # Afficher max 50
        print(f"  - {sel}")
    
    if len(unused) > 50:
        print(f"  ... et {len(unused) - 50} autres")

print(f"\n{'='*70}\n")
