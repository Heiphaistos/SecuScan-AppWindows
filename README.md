<div align="center">
  <h1>SecuScan AI</h1>
  <p><strong>Scanner de sécurité desktop Windows — YARA, PE, SAST, secrets, DPAPI, analyse IA intégrée.</strong></p>

  ![Version](https://img.shields.io/badge/version-1.0.5-blue)
  ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?logo=windows)
  ![Stack](https://img.shields.io/badge/stack-Tauri%20v2%20%2B%20Rust%20%2B%20Vue%203-purple)
  ![License](https://img.shields.io/badge/licence-MIT-green)
</div>

---

## Description

SecuScan AI est un scanner de sécurité desktop Windows distribué en un seul `.exe` portable (< 40 MB RAM). Il analyse l'intégralité d'un répertoire de projet — code source, scripts, fichiers de configuration et exécutables — puis propose des corrections automatiques via IA (Claude, Gemini). Les clés API sont chiffrées via Windows DPAPI, jamais stockées en clair.

---

## Fonctionnalités

- **Scanner YARA** — règles personnalisées : injection DLL, process hollowing, ransomware, shellcode
- **Analyse PE** — headers, imports, sections, détection ASLR/DEP/CFG manquants (via goblin)
- **SAST statique** — SQL Injection, XSS, Command Injection, Path Traversal, Open Redirect, CORS erroné, crypto faible (OWASP Top 10)
- **Détection de secrets** — entropie Shannon + 14 patterns (AWS, GCP, OpenAI, Stripe, GitHub, JWT, passwords DB…)
- **Scripts malveillants** — analyse `.bat`, `.ps1`, `.sh` : payloads encodés, élévation de privilèges, mécanismes de persistance
- **DPAPI** — stockage chiffré Windows des clés API, déchiffrement par utilisateur uniquement
- **Batch Fix automatique** — correction groupée de catégories de vulnérabilités
- **Faux positifs hints** — marquage et exclusion des faux positifs identifiés
- **Filtrage lignes longues** — évite les faux positifs sur les fichiers minifiés
- **Export TXT/HTML** — rapport détaillé avec dialog de sauvegarde natif
- **Interface par sévérité** — 4 niveaux : Critique, Haute, Moyenne, Faible

---

## Stack technique

| Couche | Technologies |
|--------|-------------|
| Desktop | Tauri v2 + WebView2 |
| Moteur de scan | Rust (tokio async + rayon scan parallèle) |
| Frontend | Vue 3 + TypeScript |
| Analyse binaire | goblin (PE headers) + yara-x (règles YARA) |
| Détection secrets | Entropie Shannon + 14 patterns fournisseurs |
| Intégration IA | Anthropic Claude + Google Gemini |
| Stockage clés | Windows DPAPI (jamais en clair) |
| Distribution | `.exe` portable, dépendance WebView2 système uniquement |

---

## Installation

### Option A — Portable (recommandée)

1. Télécharger `SecuScan-AI-v1.0.5-portable.exe` depuis la [page Releases](https://github.com/heiphaistos44-crypto/SecuScan/releases/latest).
2. Exécuter directement — aucune installation requise.
3. WebView2 est préinstallé sur Windows 10/11.

### Option B — Installeur NSIS

Télécharger et exécuter `SecuScan-AI-v1.0.5-setup.exe`.

---

## Utilisation rapide

1. Lancer **SecuScan AI**
2. Cliquer sur **Paramètres** pour ajouter vos clés API (Claude / Gemini) — chiffrées par DPAPI
3. Glisser-déposer un dossier de projet sur la zone de scan (ou **Parcourir**)
4. Consulter les résultats par sévérité : Critique > Haute > Moyenne > Faible
5. Cliquer sur une vulnérabilité → **Corriger avec IA** pour obtenir une explication + le code corrigé
6. Exporter le rapport en **TXT** ou **HTML**

---

## Build depuis les sources

**Prérequis :** Rust 1.70+, Node.js 18+, Windows 10/11

```bash
git clone https://github.com/heiphaistos44-crypto/SecuScan.git
cd SecuScan
npm install
npx tauri build
```

Artefacts dans `src-tauri/target/release/` :
- `secuscan-ai.exe` — binaire portable
- `bundle/nsis/SecuScan-AI_1.0.5_x64-setup.exe` — installeur

---

## Sécurité et confidentialité

- Les clés API sont chiffrées via **Windows DPAPI** par utilisateur, jamais stockées en clair.
- Seul le **snippet vulnérable** (± 2 lignes de contexte) est envoyé à l'IA — jamais le projet complet.
- Une boîte de dialogue de confirmation s'affiche avant tout envoi de code à un LLM externe.
- Toutes les connexions réseau utilisent **rustls** (pas de dépendance SSL système).

---

## Aperçu

> Captures disponibles lors de la prochaine release publique.

---

## Licence

MIT — © 2026 Heiphaistos
