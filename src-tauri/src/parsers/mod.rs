pub mod sast;
pub mod script;
pub mod config;
pub mod binary;

use crate::models::Vulnerability;

pub trait Parser: Send + Sync {
    fn extensions(&self) -> &[&str];
    fn scan(&self, path: &std::path::Path, content: &[u8]) -> Vec<Vulnerability>;
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
