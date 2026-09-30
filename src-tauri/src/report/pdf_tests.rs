//! Tests du rendu PDF.
use super::*;
use crate::report::tests_support::sample_doc;

#[test]
fn encode_accents_et_symboles() {
    assert_eq!(encode("éàç"), vec![0xE9, 0xE0, 0xE7]);
    assert_eq!(encode("— … œ €"), vec![0x97, b' ', 0x85, b' ', 0x9C, b' ', 0x80]);
    assert_eq!(encode("a → b"), b"a -> b".to_vec());
    assert_eq!(encode("⛔ Stop"), b"Stop".to_vec());
}

#[test]
fn chaine_pdf_echappee() {
    assert_eq!(pdf_str(b"a(b)c\\"), "(a\\(b\\)c\\\\)");
    assert_eq!(pdf_str(&[0xE9]), "(\\351)");
}

#[test]
fn wrap_respecte_la_largeur() {
    let lines = wrap(&"mot ".repeat(200), Font::Reg, 10.0, 200.0);
    assert!(lines.len() > 5);
    for l in &lines {
        assert!(width(l, Font::Reg, 10.0) <= 200.0 + 0.01);
    }
    let long = wrap(&"x".repeat(500), Font::Mono, 10.0, 100.0);
    assert!(long.iter().all(|l| width(l, Font::Mono, 10.0) <= 100.0 + 0.01));
}

#[test]
fn structure_pdf_valide() {
    let pdf = render(&sample_doc());
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(pdf.ends_with(b"%%EOF\n"));
    // Les offsets de la table xref pointent bien sur « n 0 obj ».
    let text = String::from_utf8_lossy(&pdf);
    let xref_pos: usize = text.rsplit("startxref\n").next().unwrap().lines().next().unwrap().parse().unwrap();
    assert_eq!(&pdf[xref_pos..xref_pos + 4], b"xref");
    let table = &text[xref_pos..];
    for (i, line) in table.lines().skip(3).take_while(|l| l.ends_with(" n ")).enumerate() {
        let off: usize = line[..10].parse().unwrap();
        let expect = format!("{} 0 obj", i + 1);
        assert_eq!(&pdf[off..off + expect.len()], expect.as_bytes());
    }
}

#[test]
fn long_document_multi_pages() {
    let mut doc = sample_doc();
    for i in 0..80 {
        doc.blocks.push(Block::Card {
            tone: Tone::Warn,
            title: format!("Carte {i}"),
            badges: vec![],
            body: vec![Block::Para("Texte ".repeat(60))],
        });
    }
    let pdf = render(&doc);
    let text = String::from_utf8_lossy(&pdf);
    let count = text.matches("/Type /Page ").count();
    assert!(count > 5, "{count} pages");
    assert!(text.contains(&format!("(Page {count} / {count})")));
}
