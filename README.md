# 🛡️ NuGetGuard

> PowerShell script for auditing NuGet packages in .NET solutions — finds vulnerable, deprecated and outdated dependencies in seconds.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-012456?logo=powershell)
![.NET 6+](https://img.shields.io/badge/.NET-6%2B-512BD4?logo=dotnet)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![No dependencies](https://img.shields.io/badge/dependencies-none-0075ca)

---

## ✨ Features

- **Vulnerable packages** — detects known CVEs via `dotnet list --vulnerable`, grouped by severity (Critical / High / Moderate)
- **Deprecated packages** — queries the NuGet API and shows the recommended alternative
- **Outdated packages** — shows the latest available version for every package behind
- **Export to HTML** — auto-opens a polished report in your browser
- **Export to CSV** — ready for Excel or CI artifact upload

---

## 🚀 Usage

```powershell
# Console output only (default)
.\Scan-Packages.ps1

# Export to CSV
.\Scan-Packages.ps1 -Export CSV

# Export to HTML (opens automatically in browser)
.\Scan-Packages.ps1 -Export HTML

# Custom output path
.\Scan-Packages.ps1 -Export HTML -OutputFile "C:\reports\my-project"

# Point to a specific solution folder
.\Scan-Packages.ps1 -SolutionPath "C:\Projects\MyApp"
```

---

## 📋 Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SolutionPath` | `.` | Path to the folder containing the `.sln` file |
| `-Export` | `None` | `None` / `CSV` / `HTML` |
| `-OutputFile` | `nuget-report` | Output filename without extension |

---

## ⚙️ Requirements

- PowerShell 5.1 or PowerShell 7+
- .NET SDK 6+ (`dotnet` available in `PATH`)
- Internet access (NuGet API for deprecation checks)

---

## 📊 Sample output

```
🔍 Scanning solution: MyApp.sln

━━━ 🚨 VULNERABLE PACKAGES ━━━
  📦 Newtonsoft.Json 12.0.3
     Severity : High
     Advisory : https://github.com/advisories/GHSA-5crp-9r3c-p9vr
     Projects : MyApp.Api, MyApp.Worker

━━━ ⚠️ DEPRECATED PACKAGES ━━━
  📦 Microsoft.AspNet.WebApi.Client 5.2.9
     Reason      : Legacy
     Message     : Use System.Net.Http.Json instead
     Alternative : System.Net.Http.Json [6.0.0, )
     Projects    : MyApp.Api

━━━ 📦 OUTDATED PACKAGES ━━━
  📦 Serilog 3.0.1
     Latest: 4.2.0
     Projects: MyApp.Api, MyApp.Worker

━━━ 📊 SUMMARY ━━━
  Vulnerable : 🚨 1
  Deprecated : ⚠️  1
  Outdated   : 📦 5
```

---

## 📁 Repository structure

```
NuGetGuard/
├── Scan-Packages.ps1   # Main script
└── README.md
```

---

## 💡 Tips

- Use `-Export HTML` when sharing results with your team — the report opens directly in the browser with color-coded severity badges.
- Run the script in CI/CD pipelines with `-Export CSV` to upload the report as a build artifact.
- The script auto-discovers the `.sln` file recursively — no need to `cd` into the solution folder first.

---

## 📄 License

MIT — free to use, modify and distribute.
