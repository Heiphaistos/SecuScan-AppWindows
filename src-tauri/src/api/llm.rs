//! LLM integration — Claude (Anthropic), Gemini (Google), Antigravity.
//! Sends only the vulnerable code snippet + context. Never the full project.

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::models::{AiFixResult, LlmProvider, Vulnerability};

// ─── Request builders ─────────────────────────────────────────────────────────

fn build_prompt(vuln: &Vulnerability) -> String {
    let snippet = vuln.code_snippet.as_deref().unwrap_or("[no snippet]");
    let matched = vuln.matched_pattern.as_deref().unwrap_or("");
    let cwe     = vuln.cwe_id.as_deref().unwrap_or("N/A");
    let file    = &vuln.file_path;

    format!(
        r#"You are a security expert. Analyze this vulnerability and provide a fix.

## Vulnerability Report
- **Type**: {} ({})
- **Severity**: {}
- **CWE**: {}
- **File**: {}
- **Line**: {}
- **Matched pattern**: `{}`

## Vulnerable Code
```
{}
```

## Instructions
1. Explain in 2-3 sentences what the vulnerability is and how an attacker could exploit it.
2. Provide the corrected, secure version of the code with inline comments explaining each fix.
3. Keep the fix minimal — do not refactor unrelated code.

## Response format (JSON only):
```json
{{
  "explanation": "...",
  "fixed_code": "..."
}}
```"#,
        vuln.title,
        format!("{:?}", vuln.category),
        format!("{:?}", vuln.severity),
        cwe,
        file,
        vuln.line_number.unwrap_or(0),
        matched,
        snippet
    )
}

// ─── Claude (Anthropic) ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct AnthropicRequest<'a> {
    model:      &'a str,
    max_tokens: u32,
    messages:   Vec<AnthropicMessage<'a>>,
}

#[derive(Serialize)]
struct AnthropicMessage<'a> {
    role:    &'a str,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: Option<String>,
}

async fn call_claude(
    client: &Client,
    api_key: &str,
    prompt: &str,
) -> Result<String, String> {
    let body = AnthropicRequest {
        model:      "claude-sonnet-4-6",
        max_tokens: 2048,
        messages:   vec![AnthropicMessage { role: "user", content: prompt.to_string() }],
    };

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body   = resp.text().await.unwrap_or_default();
        return Err(format!("Claude API {status}: {body}"));
    }

    let parsed: AnthropicResponse = resp.json().await.map_err(|e| e.to_string())?;
    parsed
        .content
        .into_iter()
        .find_map(|c| c.text)
        .ok_or_else(|| "Empty Claude response".to_string())
}

// ─── Gemini (Google) ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct GeminiRequest<'a> {
    contents: Vec<GeminiContent<'a>>,
    #[serde(rename = "generationConfig")]
    generation_config: GeminiGenConfig,
}

#[derive(Serialize)]
struct GeminiContent<'a> {
    parts: Vec<GeminiPart<'a>>,
}

#[derive(Serialize)]
struct GeminiPart<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct GeminiGenConfig {
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: GeminiResponseContent,
}

#[derive(Deserialize)]
struct GeminiResponseContent {
    parts: Vec<GeminiResponsePart>,
}

#[derive(Deserialize)]
struct GeminiResponsePart {
    text: Option<String>,
}

async fn call_gemini(
    client: &Client,
    api_key: &str,
    prompt: &str,
) -> Result<String, String> {
    let model = "gemini-1.5-flash";
    let url   = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    );

    let body = GeminiRequest {
        contents: vec![GeminiContent {
            parts: vec![GeminiPart { text: prompt }],
        }],
        generation_config: GeminiGenConfig {
            max_output_tokens: 2048,
            temperature: 0.2,
        },
    };

    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body   = resp.text().await.unwrap_or_default();
        return Err(format!("Gemini API {status}: {body}"));
    }

    let parsed: GeminiResponse = resp.json().await.map_err(|e| e.to_string())?;
    parsed
        .candidates
        .into_iter()
        .find_map(|c| c.content.parts.into_iter().find_map(|p| p.text))
        .ok_or_else(|| "Empty Gemini response".to_string())
}

// ─── Antigravity ─────────────────────────────────────────────────────────────

async fn call_antigravity(
    client: &Client,
    api_key: &str,
    endpoint: &str,
    prompt: &str,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct AgRequest<'a> { prompt: &'a str }

    #[derive(Deserialize)]
    struct AgResponse { result: Option<String>, text: Option<String> }

    let resp = client
        .post(endpoint)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("content-type", "application/json")
        .json(&AgRequest { prompt })
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body   = resp.text().await.unwrap_or_default();
        return Err(format!("Antigravity API {status}: {body}"));
    }

    let parsed: AgResponse = resp.json().await.map_err(|e| e.to_string())?;
    parsed.result.or(parsed.text)
        .ok_or_else(|| "Empty Antigravity response".to_string())
}

// ─── JSON extraction from LLM response ───────────────────────────────────────

fn extract_json_fix(raw: &str) -> (String, String) {
    // Try to find JSON block
    let json_start = raw.find('{').unwrap_or(0);
    let json_end   = raw.rfind('}').map(|i| i + 1).unwrap_or(raw.len());

    if json_start < json_end {
        let json_str = &raw[json_start..json_end];
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
            let explanation = v["explanation"].as_str().unwrap_or("").to_string();
            let fixed_code  = v["fixed_code"].as_str().unwrap_or("").to_string();
            if !explanation.is_empty() && !fixed_code.is_empty() {
                return (explanation, fixed_code);
            }
        }
    }

    // Fallback: return raw text as explanation
    (raw.to_string(), String::new())
}

// ─── Public entry ─────────────────────────────────────────────────────────────

pub async fn request_fix(
    vuln:             &Vulnerability,
    provider:         &LlmProvider,
    api_key:          &str,
    ag_endpoint:      Option<&str>,
) -> Result<AiFixResult, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;

    let prompt = build_prompt(vuln);

    let raw = match provider {
        LlmProvider::Claude      => call_claude(&client, api_key, &prompt).await?,
        LlmProvider::Gemini      => call_gemini(&client, api_key, &prompt).await?,
        LlmProvider::Antigravity => {
            let endpoint = ag_endpoint.unwrap_or("https://api.antigravity.ai/v1/chat");
            call_antigravity(&client, api_key, endpoint, &prompt).await?
        }
    };

    let (explanation, fixed_code) = extract_json_fix(&raw);

    Ok(AiFixResult {
        vulnerability_id: vuln.id.clone(),
        explanation,
        fixed_code,
        provider: provider.clone(),
    })
}

/// Build a clipboard-ready prompt for manual AI pasting.
pub fn build_clipboard_prompt(vuln: &Vulnerability) -> String {
    build_prompt(vuln)
}

// ─── Batch fix — one file, all its vulnerabilities ────────────────────────────

const BATCH_FILE_CAP: usize = 80 * 1024; // 80 KB per file fed to LLM

fn build_batch_prompt(file_path: &str, content: &str, vulns: &[&Vulnerability]) -> String {
    let mut vuln_list = String::new();
    for (i, v) in vulns.iter().enumerate() {
        let matched  = v.matched_pattern.as_deref().unwrap_or("[no pattern]");
        let line_str = v.line_number.map(|l| format!("line {l}")).unwrap_or_else(|| "unknown line".into());
        vuln_list.push_str(&format!(
            "{}. [{:?}] {} ({})\n   Pattern: `{}`\n   Fix hint: {}\n\n",
            i + 1,
            v.severity,
            v.title,
            line_str,
            matched,
            v.remediation,
        ));
    }

    // Cap content to avoid token overflow
    let capped_content = if content.len() > BATCH_FILE_CAP {
        &content[..BATCH_FILE_CAP]
    } else {
        content
    };

    format!(
        r#"You are a security expert. Fix ALL the following vulnerabilities in this file.
Return ONLY valid JSON — no markdown wrapper, no extra text.

File: {file_path}

Vulnerabilities to fix:
{vuln_list}
Current file content:
```
{capped_content}
```

Return exactly this JSON structure:
{{"fixed_code": "<complete corrected file content>", "summary": "<one sentence describing what was fixed>"}}"#
    )
}

/// Fix all vulnerabilities in a single file with one LLM call.
/// Returns `(patched_content, summary)`.
pub async fn batch_fix_file(
    file_path:   &str,
    content:     &str,
    vulns:       &[&Vulnerability],
    provider:    &LlmProvider,
    api_key:     &str,
    ag_endpoint: Option<&str>,
) -> Result<(String, String), String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;

    let prompt = build_batch_prompt(file_path, content, vulns);

    let raw = match provider {
        LlmProvider::Claude      => call_claude(&client, api_key, &prompt).await?,
        LlmProvider::Gemini      => call_gemini(&client, api_key, &prompt).await?,
        LlmProvider::Antigravity => {
            let ep = ag_endpoint.unwrap_or("https://api.antigravity.ai/v1/chat");
            call_antigravity(&client, api_key, ep, &prompt).await?
        }
    };

    let (summary, fixed_code) = extract_json_batch(&raw);
    if fixed_code.is_empty() {
        return Err(format!("LLM returned no fixed_code for {file_path}"));
    }
    Ok((fixed_code, summary))
}

/// Extract {"fixed_code": ..., "summary": ...} from LLM response.
fn extract_json_batch(raw: &str) -> (String, String) {
    // Find outermost JSON object
    let start = raw.find('{').unwrap_or(0);
    let end   = raw.rfind('}').map(|i| i + 1).unwrap_or(raw.len());
    if start < end {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw[start..end]) {
            let summary    = v["summary"].as_str().unwrap_or("Fixes applied.").to_string();
            let fixed_code = v["fixed_code"].as_str().unwrap_or("").to_string();
            if !fixed_code.is_empty() {
                return (summary, fixed_code);
            }
        }
    }
    (raw.chars().take(200).collect(), String::new())
}
