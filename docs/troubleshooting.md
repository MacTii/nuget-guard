# Troubleshooting

## The installed version is not the one just built

`dotnet pack` adds to its output folder without cleaning it, and `dotnet tool install` picks the **highest** version it finds there. An earlier build therefore keeps winning:

```
artifacts/
  NuGetGuard.1.1.0.nupkg   <- built earlier, still installed
  NuGetGuard.1.0.0.nupkg   <- just built, ignored
```

`artifacts/` is git-ignored, so pulling never clears it. Rebuild from a clean folder:

```powershell
git pull
Remove-Item artifacts\*.nupkg -Force
dotnet pack src\NuGetGuard\NuGetGuard.csproj -c Release -o artifacts
dotnet tool uninstall -g NuGetGuard
dotnet tool install -g NuGetGuard --add-source .\artifacts
```

Or name the version outright: `dotnet tool install -g NuGetGuard --add-source .\artifacts --version 1.0.0`.

Check what is actually installed with `dotnet tool list -g`.

## A version I no longer reference is reported

Check what the project file actually declares:

```powershell
Select-String -Path .\**\packages.config -Pattern "PackageName"
Select-String -Path .\**\*.csproj -Pattern "PackageName"
```

The tool reports what the **project files** declare, so a version that appears there but not in Visual Studio usually means one project was left behind during an upgrade — the Visual Studio package manager shows a consolidated view, while the report lists every project separately. Consolidating the version across the solution removes the finding.

The restored `packages/` folder is *not* a source of packages. It accumulates every version a solution has ever restored, so reading it would report packages that are long gone.

## Two versions of the same package are listed

Expected: different projects reference different versions, and each is reported with the projects that declare it. Consolidate them to get a single row.

## Not every project was scanned

The project list comes from the solution file. Projects on disk but not in the solution are ignored on purpose — a folder often holds several unrelated solutions, and mixing them produces a meaningless report. The header shows how many projects were found, plus a warning when other solutions exist alongside.

Point the path at the solution you want:

```bash
nuget-guard C:\Projects\MyApp\SomeOtherSolutionFolder
```

## `Solution-level vulnerable scan failed, falling back to per-project`

`dotnet list package` needs restored projects and cannot read `packages.config`. The fallback tries each project separately and lists the ones it had to skip. Vulnerability data from the NuGet API still covers every package, so the report remains complete — the fallback only affects the extra detail `dotnet list` provides for transitive packages.

Running `dotnet restore` first usually resolves it for SDK-style solutions.

## Licences stay Unknown

None of the offline steps could identify it: the package declares no SPDX expression, it is not in the built-in database, its licence URL is unrecognisable, and it ships no licence file. Packages from a private feed and commercial ones behind redirecting EULA links are the usual cases.

Try the online lookup, which curates licence data from package contents and occasionally identifies one the offline steps cannot:

```bash
nuget-guard --online-licenses
```

Expect a modest return. The offline steps already resolve almost everything, so this mainly helps old packages that ship no licence file — the case where the offline text matching has nothing to read.

Whatever is still `Unknown` after that has no published licence data anywhere — typically a package from a private feed, or an old one that never declared a licence. The report names them, so check those few by hand: read the licence file in the package, or ask whoever publishes it.

`Unknown` is not "probably fine" — it means nothing was confirmed. The tool leaves it that way on purpose rather than guessing, because a wrong licence in a compliance report is worse than an unanswered one.

## The report is not where I expected

`--output` resolves against the current directory, not the scanned path:

```bash
cd C:\Projects\MyApp
nuget-guard . --export html                                        # -> C:\Projects\MyApp\nuget-report.html
nuget-guard C:\Projects\MyApp --export html --output C:\reports\app   # -> C:\reports\app.html
```

## The scan is slow

Metadata is fetched in parallel, but every distinct package version needs a request; several hundred packages take under a minute. The two analyses that walk dependency graphs and source files are the slowest parts and can be turned off:

```bash
nuget-guard --skip-redundant --skip-unused
```

## Reports keep the earlier results

Exports overwrite the same file name. Use `--output` with a date, or a per-branch name, to keep a history.
