# NuGetGuard

Audit every NuGet package in your .NET solution in one command. Finds vulnerable, deprecated and outdated packages, classifies licence risk, and points out references you no longer need — as a terminal report or a shareable HTML page.

## Install

```bash
dotnet tool install -g NuGetGuard
```

## Use

```bash
nuget-guard                                   # scan the solution in the current directory
nuget-guard C:\Projects\MyApp                 # scan a specific folder
nuget-guard --export html                     # HTML report, opens in your browser
nuget-guard --export csv --output reports/audit
nuget-guard --fail-on vulnerable              # CI: non-zero exit when something is found
```

## What it checks

| Check | What you get |
|---|---|
| Vulnerable | Known CVEs, by severity, each linked to its advisory |
| Deprecated | Deprecated packages and the replacement the author recommends |
| Outdated | The latest stable version for everything you're behind on |
| Licences | A licence per package, classified permissive / weak copyleft / strong copyleft / proprietary / unknown |
| Redundant | References another package already pulls in — and whether removing one changes the resolved version |
| Unused | Packages whose namespaces appear nowhere in your code |

Works with SDK-style projects, legacy .NET Framework (`packages.config`), Central Package Management, and both `.sln` and `.slnx`.

The scan is read-only and stays offline by default. Package assemblies are read as metadata only — no package code is ever loaded or executed, and no build is run.

## Options

| Option | Default | Description |
|---|---|---|
| `[path]` | `.` | Folder containing the solution (searched recursively) |
| `-e, --export` | `None` | `None` / `Csv` / `Html` |
| `-o, --output` | `nuget-report` | Output filename without extension |
| `--fail-on` | `None` | `Vulnerable` / `Deprecated` / `Outdated` / `StrongCopyleft` / `Unused` / `Any` |
| `--skip-redundant` | `false` | Skip redundancy analysis |
| `--skip-unused` | `false` | Skip unused-package analysis |
| `--online-licenses` | `false` | Resolve leftover unknown licences via the ClearlyDefined API |
| `--no-open` | `false` | Don't open the HTML report |

Exit codes: `0` clean · `1` a `--fail-on` condition triggered · `2` no solution found.

## Documentation

Full documentation, including how each check works and how to read the report, is on GitHub:
[github.com/MacTii/nuget-guard](https://github.com/MacTii/nuget-guard)

MIT licensed. No telemetry.
