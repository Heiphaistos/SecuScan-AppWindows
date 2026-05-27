# SecuScan AI — Release Notes

## v1.0.0 — Initial Release (2026-05-27)

### 🚀 What's New

First public release of **SecuScan AI**, an offensive & defensive security scanner for Windows 10/11.

---

### 📦 Assets

| File | Description |
|------|-------------|
| `SecuScan-AI-v1.0.0-portable.exe` | Portable binary — run directly, no installation |
| `SecuScan-AI-v1.0.0-setup.exe` | NSIS installer with uninstaller |

**System requirement:** Windows 10/11 (WebView2 pre-installed)

---

### ✨ Features

#### Security Engine
- **SAST (Source Code)** — 18 rules covering OWASP Top 10:
  - SQL Injection (parameterized query audit)
  - XSS (innerHTML, eval, PHP superglobals, React dangerouslySetInnerHTML)
  - Command Injection, Path Traversal
  - Weak cryptography (MD5/SHA1/DES/ECB, non-CSPRNG)
  - Insecure deserialization (pickle, yaml.load, unserialize)
  - Hardcoded secrets and private keys in code
  - CORS wildcard misconfiguration
  - Open Redirect

- **Script Scanner (.bat, .ps1, .sh)** — 15 rules:
  - Encoded/obfuscated commands (-EncodedCommand, IEX)
  - Remote payload download cradles (Invoke-WebRequest, certutil, BITS, mshta)
  - Antivirus/Defender disablement (Set-MpPreference, service stop, registry)
  - Privilege escalation (runas, sensitive privileges)
  - Persistence mechanisms (scheduled tasks, Run registry keys)
  - Hidden PowerShell execution flags

- **Config & Secret Scanner (.env, .json, .yaml, .bak, etc.)** — 14 patterns + Shannon entropy:
  - AWS (Access Key ID + Secret), OpenAI, Google/GCP, Anthropic, Stripe, GitHub
  - Slack webhook URLs, JWT tokens
  - Database connection strings (MongoDB, MySQL, PostgreSQL, ADO.NET)
  - Private key material (RSA, EC, DSA, OPENSSH)
  - High-entropy string detection (>4.5 Shannon entropy)

- **Binary Scanner (.exe, .dll)** — PE + YARA:
  - PE header analysis: ASLR, DEP/NX, CFG flags
  - SHA-256 + MD5 hash computation
  - 6 embedded YARA rules: shellcode, DLL injection, process hollowing, registry persistence, ransomware indicators, UPX packer

#### AI-Assisted Remediation
- **3 providers:** Claude (Anthropic), Gemini (Google), Antigravity
- Sends only the vulnerable snippet (±2 lines) — never the full project
- Returns: vulnerability explanation + corrected code snippet
- **"Copy Prompt"** button: one-click optimized Markdown prompt for clipboard

#### Security
- API keys encrypted with **Windows DPAPI** — never stored in plaintext
- User confirmation before any code is sent to an external API

#### Reporting
- Real-time scan dashboard with severity counters
- Filter by severity, full-text search
- Export: **JSON** (structured), **CSV** (spreadsheet), **Markdown** (documentation)

#### UX
- Drag & Drop folder → instant scan
- Streaming progress (file-by-file)
- Dark cyberpunk theme, zero heavy framework
- Configurable: max file size, skip node_modules/.git, toggleable binary scan

---

### 🔧 Technical

| Component | Version |
|-----------|---------|
| Rust | 1.95 |
| Tauri | 2.x |
| yara-x | 0.9 |
| goblin (PE) | 0.9 |
| reqwest (TLS) | 0.12 + rustls |

---

### 📋 Checksums (SHA-256)

| File | SHA-256 |
|------|---------|
| `SecuScan-AI-v1.0.0-portable.exe` | `9BD365B1D3D21F68B2579C0AB05DEDF4E793F7656B6937715503396084F1418E` |
| `SecuScan-AI-v1.0.0-setup.exe` | `A1E689063D1816FC30ACEF0D3BE792EF0852BA3470CDE69D9855D56A21EDDB2E` |

---

### ⚠️ Known Limitations

- Binary scan of very large files (>50 MB) is skipped by default (configurable)
- YARA rules are embedded — external .yar file support planned for v1.1.0
- macOS/Linux not supported (Windows DPAPI dependency)

---

*SecuScan AI v1.0.0 — Built with Rust + Tauri v2*
