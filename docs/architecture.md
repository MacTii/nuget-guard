# Architecture

How the code is organised and how each feature is implemented. For behaviour rather than implementation, see [how it works](how-it-works.md) and [the checks](checks.md).

## Layers

One project, layered by folder. Dependencies point one way:

```
Commands ──► Reporting ──► Services ──► Models
   (CLI)      (output)      (logic)     (no dependencies)
```

| Folder | Holds | Rule |
|---|---|---|
| `Commands/` | `ScanCommand`, `ScanSettings`, `FailOn`, `ExitCodeResolver` | Spectre.Console.Cli lives here and nowhere else |
| `Services/` | scanning, NuGet API, licences, redundancy, unused | no console output — progress is reported through callbacks |
| `Services/DotNet/`, `Services/NuGetApi/` | external integrations + their JSON models | DTOs are `internal`, so API shapes never leak |
| `Reporting/` | `ConsoleReporter`, `HtmlExporter`, `CsvExporter` | reads the report, never computes it |
| `Models/` | the report model, one type per file | plain data + `Rankings` for ordering |

Classes with state or dependencies are instances (`NuGetClient`, `ReportBuilder`, `RedundancyAnalyzer`, `UnusedPackageAnalyzer`); pure functions are static (`ProjectFileReader`, `LicenseCatalog`, `SolutionDiscovery`). There are no interfaces — nothing has a second implementation, and the pure functions are testable as they are.

## The scan, in code

`ScanCommand.ExecuteAsync` is the only orchestrator. Everything it calls is I/O-free logic or an integration wrapper:

| Step | Call | Notes |
|---|---|---|
| Find solution | `SolutionDiscovery.Discover` | shortest path wins; extra solutions are recorded, not scanned |
| Read projects | `SolutionProjectReader.ReadProjects` | regex over `.sln`, XML over `.slnx`; falls back to the solution folder |
| Collect packages | `PackageCollector.CollectPackages` | keyed `Id\|Version`, so one package at two versions stays two entries |
| Restore legacy | `LegacyRestorer.RestoreAsync` | only when a `packages.config` exists |
| Fetch metadata | `ReportBuilder.FetchMetadataAsync` | 8-way `Parallel.ForEachAsync` |
| Resolve licences | `ReportBuilder.ResolveRemainingLicensesAsync` | second pass, only for the unresolved |
| Build sections | `ReportBuilder.Build*` | vulnerable, deprecated, outdated, licences |
| Analyse | `RedundancyAnalyzer`, `UnusedPackageAnalyzer` | skippable via CLI flags |
| Render | `ConsoleReporter.Render`, `ReportExporter.Export` | |
| Exit | `ExitCodeResolver.Resolve` | |

The progress bars and spinners live in `ScanCommand`; services take an `Action<string>` or `Action` callback so they stay printable-free and testable.

## Reading projects

`ProjectFileReader` is the single entry point for MSBuild files, deliberately XML-based rather than MSBuild-based — it must work without a restore, on legacy formats, and without evaluating the project.

It handles `PackageReference` as an attribute *and* as a child element, `packages.config`, Central Package Management (`Directory.Packages.props` supplies the version when the reference omits it), wildcard versions (skipped — they cannot be checked against an API), `<Using Include>` global usings, `ProjectReference` closure, and linked files declared outside the project folder.

Everything uses `e.Name.LocalName` rather than qualified names, because old project files carry the MSBuild namespace while SDK-style ones do not.

## The NuGet client

`NuGetClient` wraps two endpoints:

- **registration** (`registration5-gz-semver2`) — deprecation, vulnerabilities, licence, dependencies;
- **flat-container** — the version list, used for the latest stable version.

Three things matter in the implementation:

**Paging.** A registration index is split into pages carrying `lower`/`upper` version bounds. `PageMayContain` compares the target against those bounds and skips whole pages, so a package with hundreds of versions costs one request instead of many.

**Version matching.** `VersionsEqual` first compares strings, then falls back to parsed `NuGetVersion` comparison, so `1.0` and `1.0.0` match.

**Caching.** `ConcurrentDictionary<string, Task<T>>` caches the *task*, not the result — concurrent callers asking for the same package await one request instead of racing. Three caches: index, dependencies, latest version.

Failures return `null` rather than throwing: a package missing from nuget.org (internal feed, unlisted) must not abort a scan.

## Licence resolution

Four steps, first hit wins, implemented across `NuGetClient.ApplyLicense`, `LicenseCatalog` and `LicenseUrlResolver`:

1. `licenseExpression` from the API.
2. `LicenseCatalog.GetKnownLicense` — ~460 exact ids plus an *ordered* prefix table. Order matters: `microsoft.aspnetcore.` (MIT) is checked before `microsoft.aspnet.` (Apache-2.0), otherwise the shorter prefix would win.
3. `LicenseUrlResolver.ResolveFromUrlPattern` — URL shape, no request.
4. `LicenseUrlResolver.ResolveFromContentAsync` — downloads the page and matches SPDX fingerprints, ordered most specific first (AGPL before GPL, `Apache License, Version 2.0` before a bare "Apache").

`LicenseCatalog.GetRisk` then classifies the SPDX id, with a fuzzy fallback for compound expressions like `MIT OR Apache-2.0`. The GPL check excludes LGPL explicitly — substring matching would otherwise call every LGPL package strong copyleft.

## Redundancy

`RedundancyAnalyzer` answers "is this reference already provided by another one?".

For each project it builds the transitive closure of every direct reference, then reports any direct reference contained in another's closure. `WalkClosureAsync` recurses through dependency ids, guarded by a `HashSet` that doubles as the cycle guard — `visited.Add` returning false ends that branch.

Dependencies come from the local `.nuspec` first (`NuspecDependencyReader`, no network) and from the registration API otherwise. For SDK projects it additionally reports packages already referenced by a referenced project. Framework polyfills (`FrameworkPolyfills`) are never reported — they exist precisely to satisfy other packages.

## Unused packages

`UnusedPackageAnalyzer` answers "does any code touch this?", combining three helpers:

| Helper | Role |
|---|---|
| `PackageAssemblyLocator` | finds the package's `lib/` or `ref/` assemblies, in `~/.nuget/packages` or the legacy folder |
| `AssemblyNamespaceReader` | reads exported namespaces via `System.Reflection.Metadata` — `PEReader` + `MetadataReader`, never `Assembly.Load` |
| `SourceNamespaceScanner` | collects namespace-shaped tokens from source files |

The scanner is text-based, matching both `using X.Y;` (including `global`, `static`, aliases, Razor `@using`, VB `Imports`) and any dotted identifier, so fully qualified calls count. Each token is added with all its prefixes: `A.B.C` also registers `A.B` and `A`.

Comments and strings are *not* stripped, and that is intentional — the failure mode of this check is asymmetric. Calling a used package unused sends someone to break a build; missing one costs nothing. Every exclusion follows the same reasoning: tooling packages, packages without assemblies, polyfills, `packages.config` transitive entries, and projects whose legacy `packages/` folder was never restored.

## Reporting

`ScanReport` is the single input to all three renderers, so the console, HTML and CSV cannot drift apart. `Rankings` centralises ordering (severity, category) and is shared by the exporters.

`CsvExporter` flattens the grouped sections (`Redundant`, `Unused`) into `ReportItem` rows so one CSV holds every category. `HtmlExporter` builds a self-contained page — inline CSS, `rowspan` grouping per package — and `ReportExporter` picks the format and opens the browser.

## Testing

`tests/NuGetGuard.Tests` — xUnit v3 with Shouldly, no network and no build required. Tests write real temporary files (`Directory.CreateTempSubdirectory`) rather than mocking the file system, because the code under test parses real project formats and that is what needs verifying.

`UnusedPackageAnalyzerTests` copies the tool's own assembly into a fake package folder, giving a package with known namespaces without shipping a fixture binary.

Integrations (`NuGetClient`, `DotNetCli`) have no unit tests — mocking them would only prove the mock works. They are covered by running the tool against real solutions.

## Extending

**A new check.** Add the model to `Models/`, a `Build*` method to `ReportBuilder` (or a dedicated analyzer if it needs its own state), a property on `ScanReport`, rendering in all three reporters, and a `FailOn` value if it should be able to break a build. Heuristic checks stay out of `FailOn.Any`.

**A new export format.** Add the value to `ExportFormat`, the exporter to `Reporting/`, and a branch in `ReportExporter.Export`.

**A licence mapping.** Add the id to `LicenseCatalog.KnownPackageLicenses`, or a prefix to `PrefixMap` — before any shorter prefix that would also match.
