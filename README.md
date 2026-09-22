<div align="center">
  <h1>SecuScan AI</h1>
  <p><strong>Scanner de sécurité desktop Windows — YARA, PE, SAST, secrets, DPAPI, analyse IA intégrée.</strong></p>

  ![Version](https://img.shields.io/badge/version-1.1.2-blue)
  ![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?logo=windows)
  ![Stack](https://img.shields.io/badge/stack-Tauri%20v2%20%2B%20Rust-purple)
  ![License](https://img.shields.io/badge/licence-MIT-green)
</div>

---

## Description

SecuScan AI est un scanner de sécurité desktop Windows. Il analyse l'intégralité d'un répertoire de projet — code source, scripts, fichiers de configuration et exécutables — puis propose des corrections automatiques via IA (Claude, Gemini). Les clés API sont chiffrées via Windows DPAPI, jamais stockées en clair.

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
- **Export JSON / CSV / Markdown / TXT / HTML** — dialogue de sauvegarde natif
- **Mise à jour automatique** — manifeste signé, vérification au démarrage et à la demande
- **Interface par sévérité** — 4 niveaux : Critique, Haute, Moyenne, Faible

---

## Nouveautés v1.1.2

### L'export de rapport n'écrivait pas de fichier

`save_report_to_file` refusait toutes les destinations pour deux raisons cumulées :

1. Le garde-fou « la destination doit rester sous le répertoire utilisateur »
   comparait un chemin canonicalisé à `USERPROFILE`. Sous Windows,
   `std::fs::canonicalize` renvoie un chemin verbatim (`\\?\C:\Users\…`) que
   `USERPROFILE` n'a pas, et `Path::starts_with` compare les préfixes tels
   quels : la vérification était **toujours** en échec.
2. Quand le fichier n'existait pas encore, le code retenait le **dossier
   parent** comme destination. Le contrôle d'extension échouait alors, et
   l'écriture visait un dossier. L'export ne fonctionnait donc que sur un
   fichier déjà existant.

Les deux sont corrigés par un helper commun, qui canonicalise aussi le
répertoire utilisateur et recolle le nom de fichier sur le parent.
`apply_patch`, l'application d'un correctif IA, souffrait du même défaut et
partage désormais ce helper.

### Correctifs de sécurité

| Fix | Sévérité | Description |
|-----|----------|-------------|
| XSS stockée dans le rapport HTML | 🟡 MOYENNE | `cwe_id` était interpolé sans échappement, contrairement à tous les autres champs |
| Injection de formule CSV | 🟢 FAIBLE | Une cellule commençant par `=`, `+`, `-` ou `@` est exécutée par Excel et LibreOffice ; elle est désormais préfixée |

### Mise à jour automatique

L'application interroge un manifeste signé
(`secuscan-app.heiphaistos.org/maj/latest.json`) au démarrage, en silence, puis
à la demande via **Vérifier les mises à jour** dans les Paramètres. Si une
version plus récente existe, elle est proposée, téléchargée, installée, et
l'application redémarre seule.

La signature est vérifiée contre une clé publique gravée dans le binaire : un
manifeste ou un installeur modifié en route est refusé. Si le canal est
injoignable, l'application continue de fonctionner sans rien afficher.

> ⚠️ Une version antérieure à 1.1.2 ne contient pas ce module et ne se mettra
> pas à jour toute seule. Installer 1.1.2 ou plus récent une fois à la main ;
> l'automatisme prend le relais ensuite.

---

## Stack technique

| Couche | Technologies |
|--------|-------------|
| Desktop | Tauri v2 + WebView2 |
| Moteur de scan | Rust (tokio async + rayon scan parallèle) |
| Frontend | HTML/CSS/JS via `withGlobalTauri` |
| Analyse binaire | goblin (PE headers) + yara-x (règles YARA) |
| Détection secrets | Entropie Shannon + 14 patterns fournisseurs |
| Intégration IA | Anthropic Claude + Google Gemini |
| Stockage clés | Windows DPAPI (jamais en clair) |
| Mises à jour | Manifeste minisign + plugin updater Tauri |
| Distribution | Installeur NSIS, dépendance WebView2 système uniquement |

---

## Installation

Télécharger `SecuScan AI_<version>_x64-setup.exe` depuis la
[page Releases](https://github.com/Heiphaistos/SecuScan-AppWindows/releases/latest).

L'installation se fait pour l'utilisateur courant, sans élévation. Une seule
entrée apparaît dans la liste des applications de Windows, et la désinstaller
la retire entièrement. WebView2 est préinstallé sur Windows 10/11.

Les mises à jour suivantes se font toutes seules depuis l'application.

---

## Utilisation rapide

1. Lancer **SecuScan AI**
2. Cliquer sur **Paramètres** pour ajouter vos clés API (Claude / Gemini) — chiffrées par DPAPI
3. Glisser-déposer un dossier de projet sur la zone de scan (ou **Parcourir**)
4. Consulter les résultats par sévérité : Critique > Haute > Moyenne > Faible
5. Cliquer sur une vulnérabilité → **Corriger avec IA** pour obtenir une explication + le code corrigé
6. Exporter le rapport en **JSON**, **CSV**, **Markdown**, **TXT** ou **HTML**

---

## Build depuis les sources

**Prérequis :** Rust 1.70+, Node.js 18+, Windows 10/11

```bash
git clone https://github.com/Heiphaistos/SecuScan-AppWindows.git
cd SecuScan-AppWindows
npm install
npx tauri build
```

Artefacts dans `src-tauri/target/release/` :
- `secuscan-ai.exe` — binaire
- `bundle/nsis/SecuScan AI_<version>_x64-setup.exe` — installeur

> Le bundler conserve `productName` tel quel, espaces compris : le fichier
> s'appelle bien `SecuScan AI_1.1.2_x64-setup.exe`, pas `SecuScan_AI_…`.

### Publier une version

Le build doit être signé, sinon le manifeste de mise à jour ne vaut rien :

```bash
export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/secuscan-updater.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
npx tauri build
python outils/publier.py --notes "Ce qui change pour l'utilisateur."
```

`publier.py` fabrique le manifeste signé et le téléverse avec l'installeur.

> ⚠️ Sans la clé privée, les applications déjà installées refuseront toute
> mise à jour : la clé publique correspondante est gravée dans leur binaire.

---

## Sécurité et confidentialité

- Les clés API sont chiffrées via **Windows DPAPI** par utilisateur, jamais stockées en clair.
- Seul le **snippet vulnérable** (± 2 lignes de contexte) est envoyé à l'IA — jamais le projet complet.
- Une boîte de dialogue de confirmation s'affiche avant tout envoi de code à un LLM externe.
- Les écritures sur disque (export de rapport, application d'un correctif) sont restreintes au répertoire utilisateur, avec liste blanche d'extensions.
- Toutes les connexions réseau utilisent **rustls** (pas de dépendance SSL système).
- Les mises à jour sont vérifiées par signature avant installation.

---

## Licence

MIT — voir [LICENSE](LICENSE)

---

## Crédits

Développé par **[Heiphaistos](https://heiphaistos.org)**.

Bibliothèques principales : [Tauri v2](https://tauri.app),
[YARA-X](https://virustotal.github.io/yara-x/),
[goblin](https://github.com/m4b/goblin) (parsing PE),
[rayon](https://github.com/rayon-rs/rayon), [tokio](https://tokio.rs),
[rustls](https://github.com/rustls/rustls).

Analyse IA : [Anthropic Claude](https://www.anthropic.com) et
[Google Gemini](https://ai.google.dev), via vos propres clés API.

© 2026 Heiphaistos
