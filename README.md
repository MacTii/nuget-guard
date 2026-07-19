# 🛡️ NuGetGuard

> .NET tool for auditing NuGet packages in .NET solutions — finds vulnerable, deprecated, outdated and redundant dependencies, and classifies license risk. All in seconds.

![.NET 8+](https://img.shields.io/badge/.NET-8%2B-512BD4?logo=dotnet)
![dotnet tool](https://img.shields.io/badge/dotnet-tool-0075ca)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- **Vulnerable packages** — detects known CVEs via `dotnet list --vulnerable` + the NuGet API, grouped by severity (Critical / High / Moderate / Low)
- **Deprecated packages** — queries the NuGet API and shows the recommended alternative
- **Outdated packages** — shows the latest available version for every package behind
- **License audit** — resolves SPDX licenses (expression → known-package DB → license URL content) and classifies risk: 🟢 Permissive / 🟡 Weak copyleft / 🔴 Strong copyleft
- **Redundant packages** — Snitch-like analysis: direct references already covered transitively by another package or a referenced project
- **Export to HTML** — polished report, auto-opens in your browser
- **Export to CSV** — ready for Excel or CI artifact upload
- **CI-friendly** — `--fail-on vulnerable` returns a non-zero exit code to break the build
- Supports SDK-style projects, legacy `packages.config` projects and Central Package Management (`Directory.Packages.props`)

---

## 📦 Installation

### From nuget.org (once published)

```bash
dotnet tool install -g NuGetGuard
dotnet tool update -g NuGetGuard   # update to the latest version
```

### From source (GitHub clone — no nuget.org needed)

```bash
git clone https://github.com/MacTii/nuget-guard.git
cd nuget-guard
dotnet pack src/NuGetGuard/NuGetGuard.csproj -c Release -o artifacts
dotnet tool install -g NuGetGuard --add-source ./artifacts
```

The `nuget-guard` command is then available globally. To uninstall: `dotnet tool uninstall -g NuGetGuard`.

### As a local tool (per-repository, no global install)

Inside the repository where you want to use it:

```bash
dotnet new tool-manifest                                   # once per repo (creates .config/dotnet-tools.json)
dotnet tool install NuGetGuard --add-source <path-to>/nuget-guard/artifacts
dotnet tool run nuget-guard -- --export html               # or: dotnet nuget-guard
```

The manifest is committed to git, so teammates just run `dotnet tool restore` to get the same tool version.

---

## 🚀 Usage

```bash
# Scan the solution in the current directory (console output only)
nuget-guard

# Point to a specific solution folder
nuget-guard C:\Projects\MyApp

# Export to HTML (opens automatically in browser)
nuget-guard --export html

# Export to CSV
nuget-guard --export csv --output reports/my-project

# CI: fail the build when vulnerable packages are found
nuget-guard --fail-on vulnerable

# Skip the (slower) redundant-packages analysis
nuget-guard --skip-redundant
```

---

## 📋 Options

| Option | Default | Description |
|---|---|---|
| `[path]` | `.` | Path to the folder containing the `.sln` file (searched recursively) |
| `-e, --export` | `None` | `None` / `Csv` / `Html` |
| `-o, --output` | `nuget-report` | Output filename without extension |
| `--fail-on` | `None` | `None` / `Vulnerable` / `Deprecated` / `Outdated` / `StrongCopyleft` / `Any` — exit code 1 when found |
| `--skip-redundant` | `false` | Skip the redundant-packages analysis |
| `--no-open` | `false` | Don't open the HTML report in the browser |

**Exit codes:** `0` — OK (or no `--fail-on` match) · `1` — `--fail-on` condition triggered · `2` — no solution found

**Where reports are written:** `--output` is resolved against the *current working directory* (unless you pass an absolute path). `--export html` produces `<output>.html`; `--export csv` produces `<output>.csv` (issues) and `<output>-licenses.csv` (license audit). Default name is `nuget-report`.

**Supported project types:** SDK-style projects (.NET / .NET Core / .NET 5+), legacy .NET Framework projects with `packages.config` (restored via nuget.exe; vulnerabilities and outdated versions come from the NuGet API since `dotnet list` cannot parse them), Central Package Management (`Directory.Packages.props`), and both `.sln` and `.slnx` solutions.

---

## ⚙️ Requirements

- .NET 8, 9 or 10 runtime (`dotnet` on `PATH`)
- Internet access (NuGet API for deprecation, license and vulnerability metadata)

---

## 📊 Sample output

```
🔍 Scanning solution: MyApp.sln

━━━ 🚨 VULNERABLE PACKAGES ━━━
  📦 Newtonsoft.Json 12.0.1
     Severity : High
     Advisory : https://github.com/advisories/GHSA-5crp-9r3c-p9vr
     Projects : MyApp.Api, MyApp.Worker

━━━ ⚠️ DEPRECATED PACKAGES ━━━
  📦 Microsoft.AspNet.WebApi.Client 5.2.9
     Reason      : Legacy
     Alternative : System.Net.Http.Json [6.0.0, )
     Projects    : MyApp.Api

━━━ 📦 OUTDATED PACKAGES ━━━
  📦 Serilog 3.0.1
     Latest: 4.2.0
     Projects: MyApp.Api, MyApp.Worker

━━━ 📜 LICENSE AUDIT ━━━
  🟢 Permissive (2)
     📦 Newtonsoft.Json 12.0.1  [MIT]

━━━ 🔗 REDUNDANT PACKAGES (covered transitively) ━━━
  📂 MyApp.Api  (SDK)
     🔗 Newtonsoft.Json 12.0.1  ← pulled by  Microsoft.AspNet.WebApi.Client 5.2.7

━━━ 📊 SUMMARY ━━━
  Vulnerable      : 🚨 1
  Deprecated      : ⚠️ 1
  Outdated        : 📦 5
  Licenses total  : 12  (🔴 StrongCopyleft: 0  ⚪ Unknown: 1)
```

---

## 🏗️ CI/CD examples

### GitHub Actions

```yaml
- name: Audit NuGet packages
  run: |
    dotnet tool install -g NuGetGuard
    nuget-guard --export csv --output nuget-audit --fail-on vulnerable

- name: Upload audit report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: nuget-audit
    path: nuget-audit*.csv
```

### GitLab CI (`.gitlab-ci.yml`)

```yaml
nuget-audit:
  stage: test
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    # From nuget.org once published, or build from a checked-out copy of this repo:
    - dotnet tool install -g NuGetGuard || dotnet tool update -g NuGetGuard
    - export PATH="$PATH:$HOME/.dotnet/tools"
    - nuget-guard --export html --output nuget-audit --no-open --fail-on vulnerable
  artifacts:
    when: always            # keep the report even when the job fails the build
    paths:
      - nuget-audit.html
    expire_in: 30 days
  allow_failure: false       # a vulnerable package fails the pipeline
```

Scheduled nightly audit (does not block merges, just reports):

```yaml
nuget-audit-nightly:
  extends: nuget-audit
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - dotnet tool install -g NuGetGuard || true
    - export PATH="$PATH:$HOME/.dotnet/tools"
    - nuget-guard --export csv --output nuget-audit --fail-on none
  artifacts:
    paths:
      - nuget-audit*.csv
```

---

## 📁 Repository structure

```
nuget-guard/
├── NuGetGuard.slnx
├── src/NuGetGuard/            # dotnet tool source
│   ├── Commands/              # CLI layer (Spectre.Console.Cli): settings, scan command
│   ├── Services/              # application logic: scanning, licenses, redundancy
│   │   ├── DotNet/            # dotnet / nuget.exe CLI integration + JSON DTOs
│   │   └── NuGetApi/          # NuGet registration API client + DTOs
│   ├── Reporting/             # console / CSV / HTML output
│   └── Models/                # report model (one type per file)
├── tests/NuGetGuard.Tests/    # xUnit unit tests (pure logic, no network)
├── Scan-Packages.ps1          # legacy PowerShell version (same features)
└── README.md
```

---

## 🔨 Building from source

```bash
git clone https://github.com/MacTii/nuget-guard.git
cd nuget-guard
dotnet test
dotnet pack src/NuGetGuard/NuGetGuard.csproj -c Release -o artifacts
dotnet tool install -g NuGetGuard --add-source ./artifacts
```

---

## 📄 License

MIT — free to use, modify and distribute.
