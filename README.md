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

> **Note:** the package is not on nuget.org yet — publishing it there is planned. Once it lands, installation will be a single `dotnet tool install -g NuGetGuard` (and updates just `dotnet tool update -g NuGetGuard`). Until then, install from source as shown below.

Requires the .NET SDK (8 or newer). Clone, pack, install — takes under a minute:

```bash
git clone https://github.com/MacTii/nuget-guard.git
cd nuget-guard
dotnet pack src/NuGetGuard/NuGetGuard.csproj -c Release -o artifacts
dotnet tool install -g NuGetGuard --add-source ./artifacts
```

The `nuget-guard` command is then available globally in your terminal. To uninstall: `dotnet tool uninstall -g NuGetGuard`.

### As a local tool (per-repository, no global install)

Inside the repository where you want to use it:

```bash
dotnet new tool-manifest                                   # once per repo (creates the dotnet-tools.json manifest)
dotnet tool install NuGetGuard --add-source <path-to>/nuget-guard/artifacts

dotnet nuget-guard --export html                           # simplest way to run a local tool
dotnet tool run nuget-guard -- --export html               # equivalent; the first '--' separates
                                                           # dotnet's own options from the tool's options
```

> Note: with `dotnet tool run`, options like `--export` **must** come after `--`, otherwise the dotnet CLI intercepts them itself. The `dotnet nuget-guard` form needs no separator.

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

## 🏗️ CI/CD

The pipeline builds the tool straight from this repository, so no package feed is required. Once the package is published to nuget.org, the clone + pack + install steps below collapse into a single `dotnet tool install -g NuGetGuard`.

### GitLab CI (`.gitlab-ci.yml`)

```yaml
nuget-audit:
  stage: test
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    # install NuGetGuard from source
    - git clone --depth 1 https://github.com/MacTii/nuget-guard.git /tmp/ng
    - dotnet pack /tmp/ng/src/NuGetGuard/NuGetGuard.csproj -c Release -o /tmp/ng/artifacts
    - dotnet tool install -g NuGetGuard --add-source /tmp/ng/artifacts
    - export PATH="$PATH:/root/.dotnet/tools"
    # scan the checked-out repository; vulnerable packages fail the pipeline
    - nuget-guard --export html --output nuget-audit --no-open --fail-on vulnerable
  artifacts:
    when: always            # keep the report even when the job fails the build
    paths:
      - nuget-audit.html
    expire_in: 30 days
```

Scheduled nightly audit that only reports, without blocking merges — add a pipeline schedule in GitLab and:

```yaml
nuget-audit-nightly:
  extends: nuget-audit
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - git clone --depth 1 https://github.com/MacTii/nuget-guard.git /tmp/ng
    - dotnet pack /tmp/ng/src/NuGetGuard/NuGetGuard.csproj -c Release -o /tmp/ng/artifacts
    - dotnet tool install -g NuGetGuard --add-source /tmp/ng/artifacts
    - export PATH="$PATH:/root/.dotnet/tools"
    - nuget-guard --export csv --output nuget-audit --fail-on none
  artifacts:
    paths:
      - nuget-audit*.csv
```

### GitHub Actions (e.g. `.github/workflows/nuget-audit.yml`)

```yaml
- name: Install NuGetGuard
  run: |
    git clone --depth 1 https://github.com/MacTii/nuget-guard.git ${{ runner.temp }}/ng
    dotnet pack ${{ runner.temp }}/ng/src/NuGetGuard/NuGetGuard.csproj -c Release -o ${{ runner.temp }}/ng/artifacts
    dotnet tool install -g NuGetGuard --add-source ${{ runner.temp }}/ng/artifacts

- name: Audit NuGet packages
  run: nuget-guard --export csv --output nuget-audit --fail-on vulnerable

- name: Upload audit report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: nuget-audit
    path: nuget-audit*.csv
```

### Other ways to get the tool into CI

- **Vendored package** — commit the packed `.nupkg` into your repository together with a tool manifest and a `nuget.config` pointing at that folder; the pipeline then only runs `dotnet tool restore`.
- **Private feed** — push the package to a GitLab Package Registry or GitHub Packages NuGet feed and install with `--add-source <feed-url>`.

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
├── legacy/
│   └── Scan-Packages.ps1      # original PowerShell version — superseded by the tool, kept for reference
└── README.md
```

> The PowerShell script is no longer developed — it lacks Central Package Management, `.slnx`, outdated detection for `packages.config` projects and CI exit codes. Use the `nuget-guard` tool instead.

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
