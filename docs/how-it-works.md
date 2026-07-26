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

**`Resolving N unidentified licenses...`** / **`Identified M more, K left unknown`**
Licences are resolved in six steps, stopping at the first that succeeds. Everything offline comes first, so the network is only used for what is left:

1. `licenseExpression` from the NuGet API — a plain SPDX id such as `MIT`.
2. A curated database of packages a prefix cannot cover: licences that differ from their family, overrides where the package's own metadata is misleading, and proprietary packages. Entries a same-value prefix already handles were removed, so the database no longer grows for ordinary open-source packages.
3. The shape of `licenseUrl` — `opensource.org/licenses/MIT` and similar URLs identify the licence on their own, without a request.
4. **The licence file shipped inside the package.** Modern packages embed a licence file instead of linking to one, and the nuget.org page for those renders its text through scripting, so downloading it yields nothing. The restored package holds the file itself, so it is read from disk and matched against SPDX fingerprints.
5. **The ClearlyDefined API** — only with `--online-licenses`. It scans package contents and curates the declared licence, resolving packages none of the offline steps could. Off by default, because a scan should stay offline and deterministic; its sentinel values (`NOASSERTION`, `OTHER`, `LicenseRef-*`) are treated as unresolved rather than invented licences.
6. **Downloading the licence page and matching its text** — one HTTP request per package that still has an unidentified URL.

The two text-matching steps (4 and 6) share the same fingerprints, ordered most specific first: the AGPL preamble before the GPL one, `Apache License, Version 2.0` before a bare mention of Apache.

`Identified 15 more, 13 left unknown` therefore means 15 packages were classified by these steps and 13 could not be. What remains is normally genuine: commercial EULAs and packages that publish no licence metadata at all. Treat those as a compliance gap to check by hand, not as a safe default — `Unknown` means nothing was verified.

**`Solution-level vulnerable scan failed, falling back to per-project...`**
`dotnet list package` needs a restored project. When the solution as a whole cannot be analysed — typically a mix of legacy and SDK projects — each project is tried separately, and the ones that fail are listed as skipped. Vulnerability data from the registration API still covers every package, so the scan stays useful.
