# How it works

## The pipeline

```
1. Find the solution        .sln / .slnx nearest the scanned path
2. Read its projects        from the solution file, not from disk
3. Collect packages         PackageReference + packages.config + Directory.Packages.props
4. Restore legacy           nuget.exe, only when packages.config projects exist
5. Fetch metadata           NuGet registration API, 8 requests in parallel
6. Resolve licenses         second pass for anything still unidentified
7. Scan vulnerabilities     dotnet list, with a per-project fallback
8. Analyse redundancy       dependency graph of the direct references
9. Analyse unused           package namespaces vs. source files
10. Report                  console, and HTML or CSV when exported
```

## Where the data comes from

| Data | Source | Offline? |
|---|---|---|
| Declared packages | `.csproj`, `packages.config`, `Directory.Packages.props` | yes |
| Vulnerabilities | `dotnet list package --vulnerable` + registration API | no |
| Deprecations, licences, latest versions | NuGet registration and flat-container APIs | no |
| Dependency graph | local `.nuspec` files, registration API as fallback | partly |
| Package namespaces | assembly metadata of the restored packages | yes |
| Source usage | project source files | yes |

Nothing is executed: assemblies are read as metadata only, and no build is required.

## What the console messages mean

**`Scanning solution: X.sln (32 projects)`**
The projects come from the solution file. A folder holding several solutions produces a warning listing how many were skipped — scan them by pointing the path at each one.

**`Restoring legacy projects via nuget.exe...`**
Only for `packages.config` projects. The restored `packages/` folder is used for offline dependency and assembly lookups. It is never read as a list of packages — see [troubleshooting](troubleshooting.md#a-version-i-no-longer-reference-is-reported).

**`Metadata fetched for N packages`**
N is the number of distinct package + version pairs across the solution. The same package at two versions counts twice.

**`Resolving N unidentified licenses...`** / **`Resolved M additional licenses from page content`**
Licences are resolved in four steps, stopping at the first that succeeds:

1. `licenseExpression` from the NuGet API — a plain SPDX id such as `MIT`.
2. A built-in database of about 460 well-known packages, for older ones that predate SPDX expressions.
3. The shape of `licenseUrl` — `opensource.org/licenses/MIT` and similar URLs identify the licence on their own, without a request.
4. **Downloading the licence page and matching its text** — the step the two messages report. Packages that only link to a licence page get one HTTP request each, and the page is matched against SPDX fingerprints, most specific first: the AGPL preamble before the GPL one, `Apache License, Version 2.0` before a bare mention of Apache, and so on.

So `Resolved 15 additional licenses from page content` means 15 packages were classified by reading their licence pages, and the remainder stayed `Unknown`. Those are usually commercial EULAs behind redirects and packages with no licence metadata at all — worth a manual look, because an unknown licence is a compliance gap rather than a safe default.

**`Solution-level vulnerable scan failed, falling back to per-project...`**
`dotnet list package` needs a restored project. When the solution as a whole cannot be analysed — typically a mix of legacy and SDK projects — each project is tried separately, and the ones that fail are listed as skipped. Vulnerability data from the registration API still covers every package, so the scan stays useful.
