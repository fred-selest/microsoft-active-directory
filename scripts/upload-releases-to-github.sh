#!/bin/bash
# Script pour uploader les releases vers GitHub Releases
# Prerequis: GitHub CLI (gh) doit etre installe et authentifie
# Installation: https://cli.github.com/

set -e

REPO="fred-selest/microsoft-active-directory"
RELEASE_DIR="release"

# Verifier que gh est installe
if ! command -v gh &> /dev/null; then
    echo "Erreur: GitHub CLI (gh) n'est pas installe"
    echo "Installation: https://cli.github.com/"
    exit 1
fi

# Verifier l'authentification
if ! gh auth status &> /dev/null; then
    echo "Erreur: Vous devez vous authentifier avec 'gh auth login'"
    exit 1
fi

echo "Upload des releases vers GitHub Releases..."
echo "Repository: $REPO"
echo ""

# Liste des versions a uploader (de la plus ancienne a la plus recente)
VERSIONS=(
    "v1.0.0"
    "v1.1.0"
    "v1.2.0"
    "v1.3.0"
    "v1.4.0"
    "v1.4.1"
    "v1.5.0"
    "v1.6.0"
    "v1.6.1"
    "v1.7.0"
    "v1.8.0"
    "v1.8.1"
    "v1.9.0"
)

# Notes de release pour chaque version
declare -A RELEASE_NOTES
RELEASE_NOTES["v1.0.0"]="Version initiale de AD Web Interface"
RELEASE_NOTES["v1.1.0"]="Ameliorations de l'interface utilisateur"
RELEASE_NOTES["v1.2.0"]="Nouvelles fonctionnalites de gestion AD"
RELEASE_NOTES["v1.3.0"]="Ameliorations de performance"
RELEASE_NOTES["v1.4.0"]="Nouvelles fonctionnalites d'administration"
RELEASE_NOTES["v1.4.1"]="Corrections de bugs"
RELEASE_NOTES["v1.5.0"]="Ameliorations de securite"
RELEASE_NOTES["v1.6.0"]="Nouvelles fonctionnalites de reporting"
RELEASE_NOTES["v1.6.1"]="Corrections et ameliorations mineures"
RELEASE_NOTES["v1.7.0"]="Interface web amelioree"
RELEASE_NOTES["v1.8.0"]="Systeme de mise a jour automatique"
RELEASE_NOTES["v1.8.1"]="Corrections de bugs et ameliorations"
RELEASE_NOTES["v1.9.0"]="Ameliorations de stabilite"

# Creer chaque release
for VERSION in "${VERSIONS[@]}"; do
    ARCHIVE="$RELEASE_DIR/ad-web-interface-$VERSION.zip"

    if [ ! -f "$ARCHIVE" ]; then
        echo "ATTENTION: Fichier non trouve: $ARCHIVE"
        continue
    fi

    echo "Creation de la release $VERSION..."

    # Verifier si la release existe deja
    if gh release view "$VERSION" --repo "$REPO" &> /dev/null; then
        echo "  -> Release $VERSION existe deja, mise a jour..."
        gh release delete "$VERSION" --repo "$REPO" --yes 2>/dev/null || true
    fi

    # Creer la release avec le fichier
    gh release create "$VERSION" \
        --repo "$REPO" \
        --title "AD Web Interface $VERSION" \
        --notes "${RELEASE_NOTES[$VERSION]}" \
        "$ARCHIVE"

    echo "  -> Release $VERSION creee avec succes"
    echo ""
done

echo "Toutes les releases ont ete uploadees avec succes!"
echo ""
echo "Vous pouvez maintenant supprimer le dossier 'release/' du depot:"
echo "  git rm -r release/"
echo "  git commit -m 'Deplacer releases vers GitHub Releases'"
echo "  git push"
