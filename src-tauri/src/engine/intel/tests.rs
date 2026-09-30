//! Tests du décodage des sources (aucun appel réseau).

use super::sources::*;
use super::*;

const H: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

#[test]
fn virustotal_detaille() {
    let body = r#"{"data":{"attributes":{
        "last_analysis_stats":{"malicious":2,"suspicious":1,"undetected":60,"harmless":0},
        "last_analysis_results":{
            "EngA":{"category":"malicious","result":"Trojan.Gen"},
            "EngB":{"category":"malicious","result":"Trojan.Gen"},
            "EngC":{"category":"suspicious","result":"Heur.Susp"},
            "EngD":{"category":"undetected","result":null}},
        "signature_info":{"verified":"Signed","signers":"Contoso Ltd"},
        "trusted_verdict":{"verdict":"goodware","organization":"Contoso"},
        "first_submission_date":1600000000,"times_submitted":42,
        "popular_threat_classification":{"suggested_threat_label":"trojan.gen"}}}}"#;
    let (r, vt) = parse_virustotal(200, body, H);
    let vt = vt.unwrap();
    assert_eq!(r.status, IntelStatus::Suspicious);
    assert_eq!((vt.positives, vt.suspicious, vt.total), (2, 1, 63));
    assert_eq!(vt.engines.len(), 3);
    assert_eq!(vt.detection_names, vec!["Trojan.Gen"]);
    assert_eq!(vt.trusted_verdict.as_deref(), Some("goodware (Contoso)"));
    assert_eq!(vt.signature.unwrap().signers, "Contoso Ltd");
    assert!(r.summary.contains("faux positif"));
    assert_eq!(parse_virustotal(404, "", H).0.status, IntelStatus::NotFound);
    assert_eq!(parse_virustotal(429, "", H).0.status, IntelStatus::Error);
}

#[test]
fn metadefender() {
    let body = r#"{"scan_results":{"total_detected_avs":5,"total_avs":21,"scan_details":{
        "ClamAV":{"threat_found":"Win.Trojan.Agent"},"Avira":{"threat_found":""}}},
        "file_info":{"file_type_description":"Executable"}}"#;
    let r = parse_metadefender(200, body, H);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert_eq!((r.detections, r.total), (Some(5), Some(21)));
    assert_eq!(r.threat_names, vec!["Win.Trojan.Agent (ClamAV)"]);
    assert_eq!(parse_metadefender(404, "{}", H).status, IntelStatus::NotFound);
}

#[test]
fn hybrid_et_opentip() {
    let r = parse_hybrid(200, r#"{"verdict":"whitelisted","threat_score":0}"#, H);
    assert_eq!(r.status, IntelStatus::KnownGood);
    let r = parse_hybrid(200, r#"{"verdict":"malicious","threat_score":100,"vx_family":"Emotet","tags":["banker"]}"#, H);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert_eq!(r.threat_names, vec!["Emotet"]);
    let r = parse_opentip(200, r#"{"Zone":"Red","FileGeneralInfo":{"FileStatus":"Malware"},"DetectionsInfo":[{"DetectionName":"HEUR:Trojan.Win32.Generic"}]}"#, H);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert_eq!(r.threat_names, vec!["HEUR:Trojan.Win32.Generic"]);
    let r = parse_opentip(200, r#"{"Zone":"Green","FileGeneralInfo":{"FileStatus":"Clean"}}"#, H);
    assert_eq!(r.status, IntelStatus::KnownGood);
}

#[test]
fn otx_et_abusech() {
    let r = parse_otx(200, r#"{"pulse_info":{"count":2,"pulses":[{"name":"Campagne X","malware_families":[{"display_name":"AgentTesla"}]}]}}"#, H);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert_eq!(r.threat_names, vec!["AgentTesla"]);
    assert_eq!(parse_otx(200, r#"{"pulse_info":{"count":0,"pulses":[]}}"#, H).status, IntelStatus::NotFound);

    let r = parse_malwarebazaar(200, r#"{"query_status":"ok","data":[{"signature":"AgentTesla","tags":["exe"],"intelligence":{"clamav":["Win.Packed.Msil-1"]}}]}"#, H);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert_eq!(r.threat_names, vec!["AgentTesla", "Win.Packed.Msil-1"]);
    assert_eq!(parse_malwarebazaar(200, r#"{"query_status":"hash_not_found"}"#, H).status, IntelStatus::NotFound);
    assert_eq!(parse_malwarebazaar(200, r#"{"query_status":"unknown_auth_key"}"#, H).status, IntelStatus::Error);

    let r = parse_threatfox(200, r#"{"query_status":"ok","data":[{"ioc":"1.2.3.4:443","threat_type_desc":"C2","malware_printable":"Cobalt Strike","confidence_level":100}]}"#, H);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert!(r.details[0].contains("confiance 100 %"));

    let r = parse_yaraify(200, r#"{"query_status":"ok","data":{"tasks":[{"static_results":[{"rule_name":"UPX_packed"}],"clamav_results":[]}]}}"#, H);
    assert_eq!(r.status, IntelStatus::Suspicious);
}

#[test]
fn cymru_et_circl() {
    let r = parse_cymru(200, r#"{"Status":0,"Answer":[{"data":"\"1221154281 53\""}]}"#);
    assert_eq!(r.status, IntelStatus::Malicious);
    assert_eq!(r.detections, Some(53));
    assert_eq!(parse_cymru(200, r#"{"Status":3}"#).status, IntelStatus::NotFound);

    let r = parse_circl(200, r#"{"FileName":"notepad.exe","hashlookup:trust":100,"ProductCode":{"ProductName":"Windows 10","MfgCode":"Microsoft"},"source":"NSRL"}"#, H);
    assert_eq!(r.status, IntelStatus::KnownGood);
    assert!(r.summary.contains("Windows 10"));
    assert_eq!(parse_circl(404, "", H).status, IntelStatus::NotFound);
    let r = parse_circl(200, r#"{"KnownMalicious":"malware-bazaar"}"#, H);
    assert_eq!(r.status, IntelStatus::Malicious);
}

#[tokio::test]
async fn sans_cle_rien_n_est_envoye() {
    let cfg = IntelConfig::default();
    let rep = lookup_all(H, "44d88612fea8a8f36de82e1278abb02f", &cfg).await;
    assert_eq!(rep.sources.len(), 8);
    assert!(rep.sources.iter().all(|s| s.status == IntelStatus::NotConfigured));
    // Empreinte invalide : aucune requête, rapport vide.
    let rep = lookup_all("../../etc", "x", &IntelConfig { free_lookups: true, ..cfg }).await;
    assert!(rep.sources.is_empty());
}
