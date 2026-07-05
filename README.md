# 📜 License Guardian

**Dependency license compliance for GitHub Actions.** Scans your `package.json`, `requirements.txt`, `go.mod`, and `Cargo.toml` for restrictive licenses. Flags GPL, AGPL, SSPL, BSL, and more — with configurable allow/deny lists.

![GitHub Actions](https://img.shields.io/badge/github%20actions-%232671E5.svg?style=for-the-badge&logo=githubactions&logoColor=white)
![MIT License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

---

## 🚨 Why License Guardian?

You're shipping code. Your dependencies have licenses. Some of those licenses (GPL, AGPL, SSPL) can force you to open-source your entire codebase or restrict how you sell your product.

**License Guardian catches these before your lawyers do.**

| License | Risk | Why It's Flagged |
|---------|------|-----------------|
| **GPL-2.0 / GPL-3.0** | 🔴 High | Copyleft — derivative works must also be GPL. |
| **AGPL-3.0** | 🔴 Critical | Network copyleft — even SaaS use triggers open-source obligation. |
| **LGPL-2.1 / LGPL-3.0** | 🟡 Medium | Weaker copyleft, but still restrictive for static linking. |
| **SSPL-1.0** | 🔴 Critical | MongoDB's license — requires releasing your entire service stack. |
| **BSL-1.1** | 🟡 Medium | Business Source License — becomes open-source later, but restrictive now. |
| **Elastic-2.0** | 🟡 Medium | Elastic's license — limits managed service providers. |
| **CC-BY-NC-4.0** | 🟡 Medium | Non-commercial — can't use in commercial products. |

---

## 🔧 Quick Start

```yaml
name: License Compliance

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  licenses:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # One step. All your dependencies. No legal surprises.
      - uses: CodeGero/license-guardian@v1
        with:
          fail-on-restrictive: true
```

---

## 📋 Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `working-directory` | No | `.` | Directory containing package manifests. |
| `allow` | No | ` ` | Comma-separated SPDX identifiers to explicitly allow (e.g. `MIT,Apache-2.0,BSD-3-Clause`). |
| `deny` | No | ` ` | Comma-separated SPDX identifiers to deny (overrides built-in restrictive list). |
| `fail-on-restrictive` | No | `true` | Exit non-zero when restrictive licenses found. Set `false` for advisory mode. |
| `annotate` | No | `true` | Post GitHub PR annotations for violations. |
| `scan-npm` | No | `true` | Scan `package.json` dependencies (npm). |
| `scan-pip` | No | `true` | Scan `requirements.txt` dependencies (pip). |
| `scan-go` | No | `true` | Scan `go.mod` dependencies (Go). |
| `scan-cargo` | No | `true` | Scan `Cargo.toml` dependencies (Rust). |

## 📤 Outputs

| Output | Description |
|--------|-------------|
| `violations` | Number of license violations found. |
| `report` | Path to the full scan report file. |

---

## 🎯 Supported Package Managers

| Ecosystem | Manifest File | How It Works |
|-----------|---------------|--------------|
| **npm / Node.js** | `package.json` | Queries the npm registry API per package. |
| **pip / Python** | `requirements.txt` | Queries the PyPI JSON API per package. |
| **Go** | `go.mod` | Queries the Go module proxy for metadata. |
| **Cargo / Rust** | `Cargo.toml` | Queries the crates.io API per crate. |

---

## ⚙️ Advanced Usage

### Allow specific licenses

```yaml
- uses: CodeGero/license-guardian@v1
  with:
    allow: 'MIT,Apache-2.0,BSD-3-Clause,ISC,MPL-2.0'
```

### Custom deny list (only flag what you care about)

```yaml
- uses: CodeGero/license-guardian@v1
  with:
    deny: 'GPL-3.0,AGPL-3.0,SSPL-1.0'
```

### Advisory mode (don't block CI)

```yaml
- uses: CodeGero/license-guardian@v1
  with:
    fail-on-restrictive: false   # Annotates PR but doesn't fail
    annotate: true
```

### Scan only specific ecosystems

```yaml
- uses: CodeGero/license-guardian@v1
  with:
    scan-npm: true
    scan-pip: false
    scan-go: false
    scan-cargo: false
```

### Scan a monorepo subdirectory

```yaml
- uses: CodeGero/license-guardian@v1
  with:
    working-directory: './packages/backend'
```

---

## ⭐ Upgrading to Premium

The free License Guardian catches the big ones. For teams that need full compliance coverage, **[License Guardian Premium](https://kryptorious.gumroad.com/l/jbvet)** ($9 lifetime) adds:

- 📋 **Full SPDX license resolution** — resolves dual-licensed and compound license expressions
- 🔍 **Deep transitive scanning** — scans your dependencies' dependencies, not just direct deps
- 📊 **Compliance dashboard** — export a CSV/JSON compliance report for legal review
- 🧵 **Per-PR summary comment** — bot posts a clean license summary on every pull request
- 🔔 **New-dependency alerts** — get notified when a new PR adds a dependency with a risky license
- ⚖️ **Custom policy files** (`license-guardian.yml`) — define org-wide compliance policies
- 🔐 **Private registry support** — scan private npm/pip registries and internal packages
- 📈 **Trend tracking** — see how your license risk profile changes over time

👉 **[Get Premium — $9 lifetime](https://kryptorious.gumroad.com/l/jbvet)**

---

## 📦 Repository

- **GitHub:** [CodeGero/license-guardian](https://github.com/CodeGero/license-guardian)
- **Author:** [@kryptorious](https://github.com/kryptorious)
- **License:** MIT

---

## 🏗️ Built by CodeGero

More quality gate actions from CodeGero:

| Action | Category |
|--------|----------|
| [**go-guardian**](https://github.com/CodeGero/go-guardian) | All-in-one Go quality gate |
| [**rust-guardian**](https://github.com/CodeGero/rust-guardian) | All-in-one Rust quality gate |

---

<p align="center">
  <sub>Made with ❤️ by <a href="https://github.com/kryptorious">kryptorious</a> for the <a href="https://github.com/CodeGero">CodeGero</a> org</sub>
</p>
