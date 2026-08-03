# @repoguard/scanner

> **RepoGuard Security Scanner** — Standalone, high-performance security analysis engine for detecting malicious code, remote execution patterns, supply chain typosquatting, container misconfigurations, and secret leaks.

Used by the **RepoGuard GitHub App**, **RepoGuard GitHub Action**, and standalone Node.js/TypeScript applications.

---

## 🤖 Upgrade to the Full RepoGuard GitHub App

While `@repoguard/scanner` detects security threats, installing the official **RepoGuard GitHub App** gives your organization full automated remediation capabilities:

| Feature                              | `@repoguard/scanner` (CLI/Lib) | `repoguard-action` (CI) | **RepoGuard GitHub App** 🚀  |
| ------------------------------------ | :----------------------------: | :---------------------: | :--------------------------: | ---------- | --- |
| Threat Detection                     |               ✅               |           ✅            |              ✅              |
| `repoguard.yml` Support              |               ✅               |           ✅            |              ✅              |
| Workflow Annotations                 |               ❌               |           ✅            |              ✅              |
| **Automated Fix PRs (Auto-Healing)** |               ❌               |           ❌            |     **✅ Yes (1-Click)**     |
| **Interactive `/fix` Issue Command** |               ❌               |           ❌            |          **✅ Yes**          |
| **Zero CI Config Required**          |               ❌               |           ❌            | **✅ Yes (1-Click Install)** |
| <!--                                 |   **Real-Time Slack Alerts**   |           ❌            |              ❌              | **✅ Yes** | --> |

👉 **[Install the RepoGuard GitHub App](https://github.com/marketplace/repoguard-ifecodes)** to get automated Fix PRs generated for every detected threat!

---

## 📦 Installation

```bash
npm install @repoguard/scanner
# or
yarn add @repoguard/scanner
# or
pnpm add @repoguard/scanner
```

---

## 🚀 Quick Start

### Basic File Content Scan

```typescript
import { scanFileContent } from "@repoguard/scanner";

const code = `# REMOVED BY REPOGUARD: curl|bash remote execution`;
const findings = scanFileContent(code, "deploy.sh");

console.log(findings);
/*
[
  {
    rule: 'curl-pipe-bash',
    severity: 'critical',
    message: 'curl output piped directly to bash/sh (remote code execution)',
    file: 'deploy.sh',
    line: 1
  }
]
*/
```

---

## ⚙️ Repository Configuration (`repoguard.yml`)

You can customize scanner behavior per-repository using a `repoguard.yml` file placed in the repository root.

```yaml
# repoguard.yml
rules:
  workflow-unpinned-action: off # Disable specific non-critical rules
  hardcoded-secret: warn # Change severity to medium

ignore:
  paths:
    - docs/ # Skip scanning specific directories
    - examples/

severity:
  minimum: medium # Only report medium, high, and critical findings

whitelist:
  patterns:
    - "sk-test-*" # Whitelist placeholder/test secret keys
    - "EXAMPLE_*"
```

### Scanning with Configuration

```typescript
import { parseRepoConfig, scanFileContentWithConfig } from "@repoguard/scanner";

const yamlConfig = `
rules:
  workflow-unpinned-action: off
`;

const config = parseRepoConfig(yamlConfig);
const findings = scanFileContentWithConfig(code, "script.js", config);
```

---

## 🛡️ Security & Bypass Protection

To prevent malicious Pull Requests from disabling security scanning to sneak malware past RepoGuard, **critical malware and RCE rules cannot be disabled via `repoguard.yml`**.

The following rules are protected and will always execute:

- `curl-pipe-bash` (Remote Code Execution)
- `wget-pipe-shell` (Remote Code Execution)
- `reverse-shell` (Reverse Shell Connection)
- `obfuscated-base64` (Obfuscated Payload Delivery)
- `obfuscated-malware-pattern` (Obfuscated String Arrays)
- `python-exec-compile` (PyPI Obfuscated Code)
- `js-obfuscated-constructors` / `js-obfuscated-charcode` / `js-obfuscated-hex`
- `crypto-miner-keywords` (Cryptocurrency Miners)
- `event-stream-malware` / `ua-parser-js-malware` (Supply Chain Attacks)

---

## 🔑 API Reference

### `scanFileContent(content: string, filePath?: string): Finding[]`

Scans file content string against all general code rules.

### `scanWorkflowContent(content: string, filePath?: string): Finding[]`

Scans GitHub Actions workflow YAML for unpinned actions, `pull_request_target` abuses, and secret exfiltration.

### `parseRepoConfig(yamlContent: string): RepoConfig`

Parses a `repoguard.yml` string into a structured configuration object.

### `applyRepoConfig(findings: Finding[], config?: RepoConfig): Finding[]`

Applies repository configuration overrides, path exclusions, whitelist patterns, and severity filters to a list of findings.

### `shouldSkipPath(filePath: string): boolean`

Checks if a file path belongs to vendor directories, node_modules, lockfiles, or binary assets that should be skipped.

### `isBinaryPath(filePath: string): boolean`

Returns `true` if the file extension is a known binary file type (image, video, compiled binary, archive).

---

## 📄 License

MIT © [IfeCodes](https://github.com/ALADETAN-IFE)
