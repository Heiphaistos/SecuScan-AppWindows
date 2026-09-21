# -*- coding: utf-8 -*-
"""Publie une version de SecuScan AI sur le canal de mise a jour.

Meme mecanique que `Nitrite 2.0/outils/publier.py`, en plus court : SecuScan ne
livre que l'installeur NSIS, donc il n'y a ni SFX client ni chemin portable.

Ce que fait ce script, a partir d'un `npx tauri build` deja fait :

  Sur secuscan-app.heiphaistos.org/maj/ -- invisible pour le client, jamais
  telecharge a la main :
    latest.json                        manifeste signe
    secuscan-<v>-installee.exe + .sig  installeur NSIS leger

L'installeur doit avoir ete signe pendant `tauri build`, ce qui suppose
TAURI_SIGNING_PRIVATE_KEY dans l'environnement :

    export TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/secuscan-updater.key)"
    export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
    npx tauri build

Usage :
    python outils/publier.py
    python outils/publier.py --notes "Export des rapports repare."
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SORTIE = os.path.join(RACINE, "release")
VPS = "root@212.227.140.45"
VPS_DIR = "/var/www/secuscan-maj"
BASE_URL = "https://secuscan-app.heiphaistos.org/maj"
PRODUIT = "SecuScan AI"
PREFIXE = "secuscan"


def version():
    with io.open(os.path.join(RACINE, "package.json"), encoding="utf-8") as f:
        return json.load(f)["version"]


def executer(cmd, **kw):
    print("  $", os.path.basename(str(cmd[0])), " ".join(str(c) for c in cmd[1:4]))
    r = subprocess.run(cmd, cwd=RACINE, **kw)
    if r.returncode != 0:
        raise SystemExit("echec : %s (code %d)" % (cmd[0], r.returncode))
    return r


def outil(nom):
    """Chemin complet d'un outil en ligne de commande, sans passer par un shell."""
    for candidat in (nom + ".cmd", nom + ".exe", nom):
        trouve = shutil.which(candidat)
        if trouve:
            return trouve
    raise SystemExit("%s introuvable dans le PATH" % nom)


def chemins(v):
    nsis = os.path.join(RACINE, "src-tauri", "target", "release", "bundle", "nsis")
    # Le bundler NSIS garde le productName tel quel, espaces compris :
    # "SecuScan AI_1.1.2_x64-setup.exe", pas "SecuScan_AI_...".
    setup = os.path.join(nsis, "%s_%s_x64-setup.exe" % (PRODUIT, v))
    return {"setup": setup, "setup_sig": setup + ".sig"}


def verifier_build(v):
    c = chemins(v)
    for cle, p in c.items():
        if not os.path.exists(p):
            raise SystemExit(
                "%s manquant : lancer d'abord `npx tauri build` avec "
                "TAURI_SIGNING_PRIVATE_KEY dans l'environnement (%s)" % (cle, p)
            )
    return c


def lire_sig(chemin):
    with io.open(chemin, encoding="utf-8") as f:
        return f.read().strip()


def manifeste(v, url, signature, notes):
    # `notes` s'affiche DANS la fenetre de proposition, juste sous la ligne qui
    # annonce deja la version : n'y ecrire que ce qui a une valeur pour
    # l'utilisateur, ou rien.
    return json.dumps(
        {
            "version": v,
            "notes": notes,
            "pub_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "platforms": {"windows-x86_64": {"signature": signature, "url": url}},
        },
        indent=2,
    )


def sha256(chemin):
    h = hashlib.sha256()
    with io.open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    return h.hexdigest()


def publier(v, notes):
    c = verifier_build(v)
    prep = os.path.join(SORTIE, "_canal")
    if os.path.exists(prep):
        shutil.rmtree(prep)
    os.makedirs(prep)

    nom = "%s-%s-installee.exe" % (PREFIXE, v)

    # Deja signe par le bundler pendant `tauri build`.
    shutil.copyfile(c["setup"], os.path.join(prep, nom))
    shutil.copyfile(c["setup_sig"], os.path.join(prep, nom + ".sig"))

    with io.open(os.path.join(prep, "latest.json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(manifeste(v, "%s/%s" % (BASE_URL, nom), lire_sig(c["setup_sig"]), notes))

    print("  empreinte de l'installeur : %s..." % sha256(c["setup"])[:16])
    print("[canal] televersement vers %s:%s" % (VPS, VPS_DIR))
    fichiers = [os.path.join(prep, n) for n in sorted(os.listdir(prep))]
    executer([outil("scp"), "-o", "BatchMode=yes"] + fichiers + ["%s:%s/" % (VPS, VPS_DIR)])
    print("  -> %s/latest.json" % BASE_URL)


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--notes",
        default="",
        help="une phrase affichee dans la fenetre de proposition de mise a jour ; "
        "vide par defaut, le numero de version y figure deja",
    )
    a = p.parse_args()
    v = version()
    print("%s %s" % (PRODUIT, v))
    publier(v, a.notes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
