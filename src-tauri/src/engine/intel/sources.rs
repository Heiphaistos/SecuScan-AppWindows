//! Appels et décodage des réponses de chaque base de réputation.

use super::*;

// ─── VirusTotal ───────────────────────────────────────────────────────────────

pub fn parse_virustotal(status: u16, body: &str, sha256: &str) -> (IntelResult, Option<VtResult>) {
    let link = format!("https://www.virustotal.com/gui/file/{sha256}");
    if status == 404 {
        let mut r = IntelResult::new(&VT, IntelStatus::NotFound, "Fichier jamais soumis à VirusTotal.");
        r.link = Some(link);
        return (r, None);
    }
    if status >= 400 {
        return (http_error(&VT, status), None);
    }
    let Ok(json) = serde_json::from_str::<Value>(body) else {
        return (net_error(&VT, "réponse illisible".into()), None);
    };
    let a = &json["data"]["attributes"];
    let stat = |k: &str| n(a, &["last_analysis_stats", k]).unwrap_or(0).max(0) as u32;
    let (mal, susp, harmless, undet) = (stat("malicious"), stat("suspicious"), stat("harmless"), stat("undetected"));
    let total = mal + susp + harmless + undet;

    let mut engines: Vec<VtEngine> = a["last_analysis_results"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(engine, r)| {
                    let cat = r["category"].as_str()?;
                    (cat == "malicious" || cat == "suspicious").then(|| VtEngine {
                        engine: engine.clone(),
                        category: cat.to_string(),
                        result: r["result"].as_str().unwrap_or("").to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    engines.sort_by(|x, y| y.category.cmp(&x.category).then(x.engine.cmp(&y.engine)));

    let mut detection_names = Vec::new();
    for e in engines.iter().filter(|e| e.category == "malicious") {
        push_unique(&mut detection_names, e.result.clone());
    }
    detection_names.truncate(15);

    let signature = a.get("signature_info").filter(|v| v.is_object()).map(|si| VtSignature {
        verified: s(si, &["verified"]).unwrap_or_default(),
        signers: s(si, &["signers"]).unwrap_or_default(),
        product: s(si, &["product"]).unwrap_or_default(),
        description: s(si, &["description"]).unwrap_or_default(),
        copyright: s(si, &["copyright"]).unwrap_or_default(),
    });

    let trusted_verdict = s(a, &["trusted_verdict", "verdict"]).map(|v| {
        match s(a, &["trusted_verdict", "organization"]) {
            Some(org) => format!("{v} ({org})"),
            None => v,
        }
    });

    let sandbox_verdicts: Vec<String> = a["sandbox_verdicts"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(sb, v)| {
                    let cat = v["category"].as_str()?;
                    let names = str_list(v.get("malware_names"), 3);
                    Some(if names.is_empty() {
                        format!("{sb} : {cat}")
                    } else {
                        format!("{sb} : {cat} ({})", names.join(", "))
                    })
                })
                .take(8)
                .collect()
        })
        .unwrap_or_default();

    let crowdsourced_yara: Vec<String> = a["crowdsourced_yara_results"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|r| s(r, &["rule_name"])).take(10).collect())
        .unwrap_or_default();

    let vt = VtResult {
        positives: mal,
        total,
        permalink: link.clone(),
        scan_date: n(a, &["last_analysis_date"]).and_then(ts_to_date).unwrap_or_default(),
        detection_names,
        suspicious: susp,
        harmless,
        undetected: undet,
        engines,
        popular_threat_label: s(a, &["popular_threat_classification", "suggested_threat_label"]),
        reputation: n(a, &["reputation"]).unwrap_or(0),
        type_description: s(a, &["type_description"]),
        names: str_list(a.get("names"), 5),
        tags: str_list(a.get("tags"), 12),
        first_submission: n(a, &["first_submission_date"]).and_then(ts_to_date),
        times_submitted: n(a, &["times_submitted"]).unwrap_or(0).max(0) as u32,
        signature,
        trusted_verdict,
        sandbox_verdicts,
        crowdsourced_yara,
    };

    let goodware = vt.trusted_verdict.as_deref().is_some_and(|v| v.starts_with("goodware"));
    let status = if vt.positives >= 3 {
        IntelStatus::Malicious
    } else if vt.positives > 0 || vt.suspicious > 0 {
        IntelStatus::Suspicious
    } else if goodware {
        IntelStatus::KnownGood
    } else {
        IntelStatus::Clean
    };
    let summary = match status {
        IntelStatus::Malicious => format!("{} moteurs sur {} détectent une menace.", vt.positives, vt.total),
        IntelStatus::Suspicious => format!(
            "{} moteur(s) sur {} signalent le fichier ({} « suspect ») — un nombre aussi faible est souvent un faux positif heuristique.",
            vt.positives, vt.total, vt.suspicious
        ),
        IntelStatus::KnownGood => format!("0 détection sur {} moteurs et fichier attesté légitime par VirusTotal.", vt.total),
        _ => format!("Aucun des {} moteurs ne détecte de menace.", vt.total),
    };
    let mut r = IntelResult::new(&VT, status, summary);
    r.detections = Some(vt.positives);
    r.total = Some(vt.total);
    r.threat_names = vt.detection_names.iter().take(8).cloned().collect();
    if let Some(l) = &vt.popular_threat_label {
        r.details.push(format!("Famille la plus citée : {l}"));
    }
    if let Some(sig) = &vt.signature {
        if !sig.signers.is_empty() || !sig.verified.is_empty() {
            r.details.push(format!("Signature : {} — {}", or_dash(&sig.verified), or_dash(&sig.signers)));
        }
    }
    if let Some(t) = &vt.trusted_verdict {
        r.details.push(format!("Verdict de confiance VirusTotal : {t}"));
    }
    if let Some(f) = &vt.first_submission {
        r.details.push(format!("Première soumission : {f} ({} soumission(s))", vt.times_submitted));
    }
    if !vt.sandbox_verdicts.is_empty() {
        r.details.push(format!("Sandboxes : {}", vt.sandbox_verdicts.join(" ; ")));
    }
    r.link = Some(link);
    (r, Some(vt))
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() { "—" } else { s }
}

pub(super) async fn virustotal(sha256: &str, key: &str) -> (IntelResult, Option<VtResult>) {
    if key.is_empty() {
        return (not_configured(&VT), None);
    }
    let Some(c) = client() else { return (net_error(&VT, "client HTTP".into()), None) };
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    // Quota public : 4 req/min. Deux nouvelles tentatives espacées sur 429.
    for attempt in 0..3u32 {
        match send(c.get(&url).header("x-apikey", key)).await {
            Ok((429, _)) if attempt < 2 => {
                tokio::time::sleep(Duration::from_millis(700 * 2u64.pow(attempt))).await;
            }
            Ok((st, body)) => return parse_virustotal(st, &body, sha256),
            Err(e) => return (net_error(&VT, e), None),
        }
    }
    (http_error(&VT, 429), None)
}

// ─── MetaDefender Cloud (OPSWAT) ──────────────────────────────────────────────

pub fn parse_metadefender(status: u16, body: &str, sha256: &str) -> IntelResult {
    let link = Some(format!("https://metadefender.com/results/hash/{sha256}"));
    if status == 404 {
        let mut r = IntelResult::new(&MD, IntelStatus::NotFound, "Empreinte inconnue de MetaDefender.");
        r.link = link;
        return r;
    }
    if status >= 400 {
        return http_error(&MD, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&MD, "réponse illisible".into()) };
    let sr = &j["scan_results"];
    let detected = n(sr, &["total_detected_avs"]).unwrap_or(0).max(0) as u32;
    let total = n(sr, &["total_avs"]).unwrap_or(0).max(0) as u32;
    let mut names = Vec::new();
    if let Some(m) = sr["scan_details"].as_object() {
        for (engine, d) in m {
            if let Some(t) = s(d, &["threat_found"]) {
                push_unique(&mut names, format!("{t} ({engine})"));
            }
        }
    }
    names.truncate(10);
    let status = if detected >= 3 {
        IntelStatus::Malicious
    } else if detected > 0 {
        IntelStatus::Suspicious
    } else {
        IntelStatus::Clean
    };
    let summary = match status {
        IntelStatus::Clean => format!("Aucun des {total} moteurs ne détecte de menace."),
        _ => format!("{detected} moteur(s) sur {total} détectent une menace."),
    };
    let mut r = IntelResult::new(&MD, status, summary);
    r.detections = Some(detected);
    r.total = Some(total);
    r.threat_names = names;
    if let Some(v) = s(&j, &["file_info", "file_type_description"]) {
        r.details.push(format!("Type : {v}"));
    }
    if let Some(v) = s(&j, &["malware_family"]).or_else(|| s(&j, &["threat_name"])) {
        r.details.push(format!("Famille : {v}"));
    }
    if let Some(v) = s(&j, &["sandbox_verdict", "verdict"]) {
        r.details.push(format!("Verdict sandbox : {v}"));
    }
    r.link = link;
    r
}

pub(super) async fn metadefender(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&MD);
    }
    let Some(c) = client() else { return net_error(&MD, "client HTTP".into()) };
    match send(c.get(format!("https://api.metadefender.com/v4/hash/{sha256}")).header("apikey", key)).await {
        Ok((st, body)) => parse_metadefender(st, &body, sha256),
        Err(e) => net_error(&MD, e),
    }
}

// ─── Hybrid Analysis (CrowdStrike Falcon Sandbox) ─────────────────────────────

pub fn parse_hybrid(status: u16, body: &str, sha256: &str) -> IntelResult {
    let link = Some(format!("https://www.hybrid-analysis.com/sample/{sha256}"));
    if status == 404 {
        let mut r = IntelResult::new(&HA, IntelStatus::NotFound, "Fichier jamais analysé en sandbox.");
        r.link = link;
        return r;
    }
    if status >= 400 {
        return http_error(&HA, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&HA, "réponse illisible".into()) };
    let verdict = s(&j, &["verdict"]).unwrap_or_default().to_lowercase();
    let score = n(&j, &["threat_score"]);
    let family = s(&j, &["vx_family"]);
    let (st, summary) = match verdict.as_str() {
        "malicious" => (IntelStatus::Malicious, "Comportement malveillant observé en sandbox.".to_string()),
        "suspicious" => (IntelStatus::Suspicious, "Comportement suspect observé en sandbox.".to_string()),
        "whitelisted" => (IntelStatus::KnownGood, "Fichier sur liste blanche Hybrid Analysis.".to_string()),
        "no specific threat" => (IntelStatus::Clean, "Aucune menace spécifique observée à l'exécution.".to_string()),
        _ => (IntelStatus::NotFound, "Pas de verdict disponible.".to_string()),
    };
    let mut r = IntelResult::new(&HA, st, summary);
    if let Some(sc) = score {
        r.details.push(format!("Score de menace sandbox : {sc}/100"));
    }
    if let Some(ms) = n(&j, &["multiscan_result"]) {
        r.details.push(format!("Détection multi-antivirus : {ms} %"));
    }
    if let Some(f) = family {
        r.threat_names.push(f);
    }
    let tags = str_list(j.get("tags"), 8);
    if !tags.is_empty() {
        r.details.push(format!("Étiquettes : {}", tags.join(", ")));
    }
    r.link = link;
    r
}

pub(super) async fn hybrid(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&HA);
    }
    let Some(c) = client() else { return net_error(&HA, "client HTTP".into()) };
    let req = c
        .get(format!("https://www.hybrid-analysis.com/api/v2/overview/{sha256}"))
        .header("api-key", key)
        .header("accept", "application/json")
        .header("user-agent", "Falcon Sandbox");
    match send(req).await {
        Ok((st, body)) => parse_hybrid(st, &body, sha256),
        Err(e) => net_error(&HA, e),
    }
}

// ─── Kaspersky OpenTIP ────────────────────────────────────────────────────────

pub fn parse_opentip(status: u16, body: &str, sha256: &str) -> IntelResult {
    let link = Some(format!("https://opentip.kaspersky.com/{sha256}/results"));
    if status == 404 {
        let mut r = IntelResult::new(&KL, IntelStatus::NotFound, "Empreinte inconnue de Kaspersky.");
        r.link = link;
        return r;
    }
    if status >= 400 {
        return http_error(&KL, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&KL, "réponse illisible".into()) };
    let zone = s(&j, &["Zone"]).unwrap_or_default();
    let file_status = s(&j, &["FileGeneralInfo", "FileStatus"]).unwrap_or_default();
    let (st, summary) = match zone.as_str() {
        "Red" => (IntelStatus::Malicious, format!("Classé MALVEILLANT par Kaspersky ({file_status}).")),
        "Orange" | "Yellow" => (
            IntelStatus::Suspicious,
            format!("Classé à risque par Kaspersky ({file_status}) — souvent adware ou outil à double usage."),
        ),
        "Green" => (IntelStatus::KnownGood, "Classé comme fichier sain par Kaspersky.".to_string()),
        _ => (IntelStatus::NotFound, "Réputation inconnue chez Kaspersky.".to_string()),
    };
    let mut r = IntelResult::new(&KL, st, summary);
    if let Some(arr) = j["DetectionsInfo"].as_array() {
        for d in arr.iter().take(8) {
            if let Some(name) = s(d, &["DetectionName"]) {
                push_unique(&mut r.threat_names, name);
            }
        }
    }
    if let Some(v) = s(&j, &["FileGeneralInfo", "Signer"]) {
        r.details.push(format!("Signataire : {v}"));
    }
    if let Some(v) = s(&j, &["FileGeneralInfo", "Packer"]) {
        r.details.push(format!("Packer : {v}"));
    }
    if let Some(v) = s(&j, &["FileGeneralInfo", "FirstSeen"]) {
        r.details.push(format!("Vu pour la première fois : {v}"));
    }
    if let Some(v) = n(&j, &["FileGeneralInfo", "HitsCount"]) {
        r.details.push(format!("Nombre d'observations : {v}"));
    }
    r.link = link;
    r
}

pub(super) async fn opentip(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&KL);
    }
    let Some(c) = client() else { return net_error(&KL, "client HTTP".into()) };
    let req = c
        .get("https://opentip.kaspersky.com/api/v1/search/hash")
        .query(&[("request", sha256)])
        .header("x-api-key", key);
    match send(req).await {
        Ok((st, body)) => parse_opentip(st, &body, sha256),
        Err(e) => net_error(&KL, e),
    }
}

// ─── AlienVault OTX ───────────────────────────────────────────────────────────

pub fn parse_otx(status: u16, body: &str, sha256: &str) -> IntelResult {
    let link = Some(format!("https://otx.alienvault.com/indicator/file/{sha256}"));
    if status == 404 {
        let mut r = IntelResult::new(&OTX, IntelStatus::NotFound, "Aucun rapport de menace ne cite ce fichier.");
        r.link = link;
        return r;
    }
    if status >= 400 {
        return http_error(&OTX, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&OTX, "réponse illisible".into()) };
    let count = n(&j, &["pulse_info", "count"]).unwrap_or(0).max(0) as u32;
    let mut families = Vec::new();
    let mut pulses = Vec::new();
    if let Some(arr) = j["pulse_info"]["pulses"].as_array() {
        for p in arr {
            if let Some(fams) = p["malware_families"].as_array() {
                for f in fams {
                    if let Some(name) = s(f, &["display_name"]).or_else(|| f.as_str().map(String::from)) {
                        push_unique(&mut families, name);
                    }
                }
            }
            if let Some(name) = s(p, &["name"]) {
                if pulses.len() < 4 {
                    pulses.push(name);
                }
            }
        }
    }
    let mut r = if count == 0 {
        IntelResult::new(&OTX, IntelStatus::NotFound, "Aucun rapport de menace ne cite ce fichier.")
    } else if !families.is_empty() {
        IntelResult::new(
            &OTX,
            IntelStatus::Malicious,
            format!("Cité dans {count} rapport(s) de menace, associé à une famille de malware."),
        )
    } else {
        IntelResult::new(
            &OTX,
            IntelStatus::Suspicious,
            format!("Cité dans {count} rapport(s) de menace communautaire(s)."),
        )
    };
    r.detections = (count > 0).then_some(count);
    families.truncate(8);
    r.threat_names = families;
    for p in pulses {
        r.details.push(format!("Rapport : {p}"));
    }
    r.link = link;
    r
}

pub(super) async fn otx(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&OTX);
    }
    let Some(c) = client() else { return net_error(&OTX, "client HTTP".into()) };
    let req = c
        .get(format!("https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"))
        .header("X-OTX-API-KEY", key);
    match send(req).await {
        Ok((st, body)) => parse_otx(st, &body, sha256),
        Err(e) => net_error(&OTX, e),
    }
}

// ─── abuse.ch : MalwareBazaar, ThreatFox, YARAify ─────────────────────────────

pub fn parse_malwarebazaar(status: u16, body: &str, sha256: &str) -> IntelResult {
    if status >= 400 {
        return http_error(&MB, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&MB, "réponse illisible".into()) };
    match j["query_status"].as_str().unwrap_or("") {
        "ok" => {}
        "hash_not_found" | "no_results" => {
            return IntelResult::new(&MB, IntelStatus::NotFound, "Absent de la base d'échantillons malveillants.")
        }
        other => return net_error(&MB, format!("réponse « {other} »")),
    }
    let d = &j["data"][0];
    let sig = s(d, &["signature"]);
    let mut r = IntelResult::new(
        &MB,
        IntelStatus::Malicious,
        match &sig {
            Some(f) => format!("Échantillon malveillant référencé (famille {f})."),
            None => "Échantillon malveillant référencé.".to_string(),
        },
    );
    if let Some(f) = sig {
        r.threat_names.push(f);
    }
    for c in str_list(d.get("intelligence").and_then(|i| i.get("clamav")), 5) {
        push_unique(&mut r.threat_names, c);
    }
    if let Some(v) = s(d, &["first_seen"]) {
        r.details.push(format!("Signalé pour la première fois : {v}"));
    }
    if let Some(v) = s(d, &["file_name"]) {
        r.details.push(format!("Nom d'origine : {v}"));
    }
    if let Some(v) = s(d, &["delivery_method"]) {
        r.details.push(format!("Vecteur de diffusion : {v}"));
    }
    let tags = str_list(d.get("tags"), 8);
    if !tags.is_empty() {
        r.details.push(format!("Étiquettes : {}", tags.join(", ")));
    }
    r.link = Some(format!("https://bazaar.abuse.ch/sample/{sha256}/"));
    r
}

pub fn parse_threatfox(status: u16, body: &str, sha256: &str) -> IntelResult {
    if status >= 400 {
        return http_error(&TF, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&TF, "réponse illisible".into()) };
    match j["query_status"].as_str().unwrap_or("") {
        "ok" => {}
        "no_result" | "no_results" | "hash_not_found" => {
            return IntelResult::new(&TF, IntelStatus::NotFound, "Aucun indicateur de campagne active associé.")
        }
        other => return net_error(&TF, format!("réponse « {other} »")),
    }
    let items = j["data"].as_array().cloned().unwrap_or_default();
    let mut r = IntelResult::new(
        &TF,
        IntelStatus::Malicious,
        format!("Associé à {} indicateur(s) de campagne malveillante active.", items.len()),
    );
    r.detections = Some(items.len() as u32);
    for it in items.iter().take(6) {
        if let Some(m) = s(it, &["malware_printable"]) {
            push_unique(&mut r.threat_names, m);
        }
        let ty = s(it, &["threat_type_desc"]).or_else(|| s(it, &["threat_type"])).unwrap_or_default();
        let conf = n(it, &["confidence_level"]).map(|c| format!(" — confiance {c} %")).unwrap_or_default();
        if let Some(ioc) = s(it, &["ioc"]) {
            r.details.push(format!("{ty} : {ioc}{conf}"));
        }
    }
    r.link = Some(format!("https://threatfox.abuse.ch/browse.php?search=hash%3A{sha256}"));
    r
}

pub fn parse_yaraify(status: u16, body: &str, sha256: &str) -> IntelResult {
    if status >= 400 {
        return http_error(&YF, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&YF, "réponse illisible".into()) };
    match j["query_status"].as_str().unwrap_or("") {
        "ok" => {}
        "not_found" | "no_results" | "hash_not_found" => {
            return IntelResult::new(&YF, IntelStatus::NotFound, "Jamais analysé par YARAify.")
        }
        other => return net_error(&YF, format!("réponse « {other} »")),
    }
    let mut rules = Vec::new();
    let mut clamav = Vec::new();
    if let Some(tasks) = j["data"]["tasks"].as_array() {
        for t in tasks {
            if let Some(sr) = t["static_results"].as_array() {
                for x in sr {
                    if let Some(name) = s(x, &["rule_name"]) {
                        push_unique(&mut rules, name);
                    }
                }
            }
            for c in str_list(t.get("clamav_results"), 5) {
                push_unique(&mut clamav, c);
            }
        }
    }
    let status = if !clamav.is_empty() {
        IntelStatus::Malicious
    } else if !rules.is_empty() {
        IntelStatus::Suspicious
    } else {
        IntelStatus::Clean
    };
    let summary = match status {
        IntelStatus::Malicious => format!("Détecté par ClamAV et {} règle(s) YARA publique(s).", rules.len()),
        IntelStatus::Suspicious => format!(
            "{} règle(s) YARA publique(s) déclenchée(s) — certaines règles sont génériques (packer, installeur…).",
            rules.len()
        ),
        _ => "Analysé, aucune règle ne se déclenche.".to_string(),
    };
    let mut r = IntelResult::new(&YF, status, summary);
    r.threat_names = clamav;
    if !rules.is_empty() {
        rules.truncate(10);
        r.details.push(format!("Règles : {}", rules.join(", ")));
    }
    r.link = Some(format!("https://yaraify.abuse.ch/sample/{sha256}/"));
    r
}

async fn abusech_post(src: &Source, url: &str, key: &str, req_body: ReqBody<'_>) -> Result<(u16, String), IntelResult> {
    let Some(c) = client() else { return Err(net_error(src, "client HTTP".into())) };
    let req = c.post(url).header("Auth-Key", key);
    let req = match req_body {
        ReqBody::Form(f) => req.form(f),
        ReqBody::Json(v) => req.json(v),
    };
    send(req).await.map_err(|e| net_error(src, e))
}

enum ReqBody<'a> {
    Form(&'a [(&'a str, &'a str)]),
    Json(&'a Value),
}

pub(super) async fn malwarebazaar(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&MB);
    }
    let form = [("query", "get_info"), ("hash", sha256)];
    match abusech_post(&MB, "https://mb-api.abuse.ch/api/v1/", key, ReqBody::Form(&form)).await {
        Ok((st, body)) => parse_malwarebazaar(st, &body, sha256),
        Err(r) => r,
    }
}

pub(super) async fn threatfox(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&TF);
    }
    let body = serde_json::json!({ "query": "search_hash", "hash": sha256 });
    match abusech_post(&TF, "https://threatfox-api.abuse.ch/api/v1/", key, ReqBody::Json(&body)).await {
        Ok((st, b)) => parse_threatfox(st, &b, sha256),
        Err(r) => r,
    }
}

pub(super) async fn yaraify(sha256: &str, key: &str) -> IntelResult {
    if key.is_empty() {
        return not_configured(&YF);
    }
    let body = serde_json::json!({ "query": "lookup_hash", "search_term": sha256 });
    match abusech_post(&YF, "https://yaraify-api.abuse.ch/api/v1/", key, ReqBody::Json(&body)).await {
        Ok((st, b)) => parse_yaraify(st, &b, sha256),
        Err(r) => r,
    }
}

// ─── Team Cymru Malware Hash Registry (DNS over HTTPS, sans clé) ──────────────

pub fn parse_cymru(status: u16, body: &str) -> IntelResult {
    if status >= 400 {
        return http_error(&CY, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&CY, "réponse illisible".into()) };
    let dns_status = n(&j, &["Status"]).unwrap_or(-1);
    if dns_status == 3 {
        return IntelResult::new(&CY, IntelStatus::NotFound, "Empreinte absente du registre (aucun antivirus ne la connaît comme malware).");
    }
    // Réponse TXT : "<horodatage> <pourcentage de détection>"
    let txt = j["Answer"]
        .as_array()
        .and_then(|a| a.iter().find_map(|x| x["data"].as_str()))
        .map(|d| d.trim_matches('"').to_string());
    let Some(txt) = txt else {
        return IntelResult::new(&CY, IntelStatus::NotFound, "Empreinte absente du registre.");
    };
    let mut parts = txt.split_whitespace();
    let ts = parts.next().and_then(|t| t.parse::<i64>().ok());
    let pct = parts.next().and_then(|p| p.parse::<u32>().ok()).unwrap_or(0).min(100);
    let status = if pct >= 30 { IntelStatus::Malicious } else { IntelStatus::Suspicious };
    let mut r = IntelResult::new(
        &CY,
        status,
        format!("Connu comme malware : {pct} % des antivirus suivis par le registre le détectent."),
    );
    r.detections = Some(pct);
    r.total = Some(100);
    if let Some(d) = ts.and_then(ts_to_date) {
        r.details.push(format!("Dernière observation : {d}"));
    }
    r.link = Some("https://hash.cymru.com/".to_string());
    r
}

pub(super) async fn cymru(md5: &str) -> IntelResult {
    let Some(c) = client() else { return net_error(&CY, "client HTTP".into()) };
    let req = c
        .get("https://cloudflare-dns.com/dns-query")
        .query(&[("name", format!("{md5}.malware.hash.cymru.com")), ("type", "TXT".to_string())])
        .header("accept", "application/dns-json");
    match send(req).await {
        Ok((st, body)) => parse_cymru(st, &body),
        Err(e) => net_error(&CY, e),
    }
}

// ─── CIRCL hashlookup (fichiers légitimes connus, sans clé) ───────────────────

pub fn parse_circl(status: u16, body: &str, sha256: &str) -> IntelResult {
    if status == 404 {
        return IntelResult::new(
            &CI,
            IntelStatus::NotFound,
            "Absent des bases de fichiers légitimes (normal pour un fichier récent ou peu diffusé).",
        );
    }
    if status >= 400 {
        return http_error(&CI, status);
    }
    let Ok(j) = serde_json::from_str::<Value>(body) else { return net_error(&CI, "réponse illisible".into()) };
    let trust = n(&j, &["hashlookup:trust"]).unwrap_or(50);
    let product = s(&j, &["ProductCode", "ProductName"]);
    let vendor = s(&j, &["ProductCode", "MfgCode"]);
    let mut r = if let Some(src) = s(&j, &["KnownMalicious"]) {
        IntelResult::new(&CI, IntelStatus::Malicious, format!("Référencé comme malveillant ({src})."))
    } else if trust >= 50 {
        IntelResult::new(
            &CI,
            IntelStatus::KnownGood,
            format!(
                "Fichier LÉGITIME connu{} — indice de confiance {trust}/100.",
                product.as_deref().map(|p| format!(" (logiciel « {p} »)")).unwrap_or_default()
            ),
        )
    } else {
        IntelResult::new(&CI, IntelStatus::Clean, format!("Connu de la base, confiance faible ({trust}/100)."))
    };
    if let Some(v) = s(&j, &["FileName"]) {
        r.details.push(format!("Nom de fichier référencé : {v}"));
    }
    if let Some(v) = vendor {
        r.details.push(format!("Éditeur : {v}"));
    }
    if let Some(v) = s(&j, &["source"]) {
        r.details.push(format!("Source : {v}"));
    }
    if let Some(v) = n(&j, &["hashlookup:parent-total"]) {
        r.details.push(format!("Présent dans {v} paquet(s) / distribution(s) logicielle(s)"));
    }
    r.link = Some(format!("https://hashlookup.circl.lu/lookup/sha256/{sha256}"));
    r
}

pub(super) async fn circl(sha256: &str) -> IntelResult {
    let Some(c) = client() else { return net_error(&CI, "client HTTP".into()) };
    let req = c
        .get(format!("https://hashlookup.circl.lu/lookup/sha256/{sha256}"))
        .header("accept", "application/json");
    match send(req).await {
        Ok((st, body)) => parse_circl(st, &body, sha256),
        Err(e) => net_error(&CI, e),
    }
}
