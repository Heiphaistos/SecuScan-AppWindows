pub mod sast;
pub mod script;
pub mod config;
pub mod binary;

use crate::models::Vulnerability;

pub trait Parser: Send + Sync {
    fn extensions(&self) -> &[&str];
    fn scan(&self, path: &std::path::Path, content: &[u8]) -> Vec<Vulnerability>;
}

/// Drop lines longer than `max_len` bytes before regex scanning.
/// Protects against catastrophic backtracking on generated/minified code
/// (single lines of hundreds of KB trigger O(n²) backtracking in some patterns).
pub fn filter_long_lines(text: &str, max_len: usize) -> Option<String> {
    if text.lines().any(|l| l.len() > max_len) {
        Some(
            text.lines()
                .filter(|l| l.len() <= max_len)
                .collect::<Vec<_>>()
                .join("\n"),
        )
    } else {
        None // no allocation when not needed
    }
}

/// True if the line is a pure comment (leading comment marker only).
/// Used by code parsers (sast/script) to drop findings on non-executed lines,
/// cutting false positives. NOT used for secret/config scanning — a commented
/// secret is still a real leak in version control.
pub fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
        || t.starts_with('#') && !t.starts_with("#!")   // shebang is not a comment finding, but keep exec intent off
        || t.starts_with("/*")
        || t.starts_with("<!--")
        || t.starts_with("::")
        || {
            let lower = t.get(..4).map(|s| s.to_ascii_lowercase());
            lower.as_deref() == Some("rem ")
        }
}

/// Extract context lines around a match.
pub fn context_snippet(lines: &[&str], line_idx: usize, context: usize) -> String {
    let start = line_idx.saturating_sub(context);
    let end    = (line_idx + context + 1).min(lines.len());
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, l)| format!("{:>4} | {}", start + i + 1, l))
        .collect::<Vec<_>>()
        .join("\n")
}
