# The checks

## 🚨 Vulnerable

Known CVEs for the exact versions in the solution, from `dotnet list package --vulnerable` merged with the NuGet registration API. Severities are Critical, High, Moderate and Low; each finding links to its GitHub advisory.

Most findings in a healthy project are **transitive** — a package you never referenced, pulled in by one you did. Fixing them usually means bumping the direct reference that brings them in rather than adding a reference to the vulnerable package itself. `dotnet nuget why <project> <package>` shows the chain.

Use `--fail-on vulnerable` to break a build on any finding.

## ⚠️ Deprecated

Packages the author marked as deprecated on nuget.org, with the reason (`Legacy`, `CriticalBugs`, `Other`) and the recommended replacement.

Alternatives are shown in NuGet version-range notation: `[6.5.1, )` means 6.5.1 or newer. The replacement is sometimes the same package at a higher version, which simply means the version in use is no longer supported.

## 📦 Outdated

The newest stable release for everything behind it; prereleases are ignored. SDK-style projects are compared through `dotnet list package --outdated`; `packages.config` projects go through the NuGet API instead, because `dotnet list` cannot read them.

## 📜 Licences

An SPDX licence per package, classified by risk:

| Risk | Examples | Why it matters |
|---|---|---|
| 🟢 Permissive | MIT, Apache-2.0, BSD, MS-PL | Attribution is normally the only obligation |
| 🟡 Weak copyleft | LGPL, MPL-2.0, EPL | Modifications to the library usually have to be published |
| 🔴 Strong copyleft | GPL, AGPL | Can extend to your own code — AGPL reaches network use |
| 🔒 Proprietary | `Commercial`, `MS-EULA` | A known licence, but not open source — the terms govern what you may do |
| ⚪ Unknown | missing or unreadable metadata | Nothing could be verified, so someone has to look |

🔴, 🔒 and ⚪ all deserve a look before shipping commercially. A common finding is a PDF or reporting library under AGPL-3.0, which needs a paid licence for closed-source products.

🔒 uses two labels that are not SPDX ids: `Commercial` for known paid products, and `MS-EULA` for the Microsoft .NET Library terms that many older Microsoft packages ship instead of an open-source licence. They are separated from ⚪ deliberately — "this is a Microsoft EULA" and "nobody could tell" lead to different work.

See [how licences are resolved](how-it-works.md#what-the-console-messages-mean).

## 🔗 Redundant

Direct references another direct reference — or a referenced project — already pulls in. The reference is superfluous, not the package.

Removing one is a judgement call. If your code uses the package directly, keeping the explicit reference is defensible: relying on someone else's dependency means an upgrade elsewhere can remove your access to it without warning. If your code never touches it, drop the line.

**Version mismatches are flagged** in the *Note* column, both when the package is covered transitively and when it comes from a referenced project:

- same version → removing the explicit reference is a safe no-op, so the note is blank;
- covered transitively at a different floor → **⚠ version differs — transitive brings X**, where X is the version the covering chain would resolve to if you dropped your reference. A package pinned *above* the floor drops to it on removal; one pinned *below* it (like Autofac 4.9.1 while a package needs ≥ 6.0.0) reveals an outright version conflict NuGet resolves in the floor's favour;
- from a referenced project at a different version → **⚠ version differs — removing changes it**.

In `packages.config` projects these findings are **informational only** — that file lists the full closure by design, so there is nothing to remove.

## 🧹 Possibly unused

Packages whose namespaces appear nowhere in the source. For each direct reference the tool reads the namespaces its assemblies export — metadata only, nothing is loaded — and looks for them in every source file, `<Using Include="…" />` global usings included.

The check is deliberately biased towards silence, because calling a used package unused is the harmful mistake:

- comments and strings are searched too, so a mention anywhere counts as usage;
- build-time, analyzer and test-runner packages are skipped;
- packages that ship no assemblies are skipped;
- framework polyfills are skipped;
- in `packages.config` projects, anything another listed package depends on is skipped — and if the `packages/` folder was not restored, the project is skipped entirely rather than reported wholesale.

Findings are still **candidates**. Packages reached only through configuration, dependency injection or reflection have no namespace in the source and will be listed — PowerShell SDK packages and runtime hosts are typical examples. Verify before removing.

Because it is heuristic, this check is excluded from `--fail-on Any`; request it with `--fail-on Unused`.
