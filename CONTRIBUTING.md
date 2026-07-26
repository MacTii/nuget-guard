# Contributing to NuGetGuard

Thanks for taking the time — bug reports, licence-database additions and features are all welcome.

## Getting set up

```bash
git clone https://github.com/MacTii/nuget-guard.git
cd nuget-guard
dotnet test          # 165 tests, no network required
dotnet run --project src/NuGetGuard -- <path-to-a-solution>
```

You need the .NET SDK 8 or newer. That's the only prerequisite — the tests hit neither the network nor a real build.

## Before opening a pull request

- `dotnet test` passes.
- New behaviour has a test. The suite favours real temporary files over mocks, because the code parses real project and package formats — copy the pattern in `tests/NuGetGuard.Tests`.
- One change per pull request, with a short description of what and why.

## Adding a licence mapping

If a package shows as `Unknown` but has a known licence, that's a useful contribution — but **verify it at the source**, don't guess. Read the licence file the package ships or its repository, then:

- a licence that differs from its family → add it to `KnownPackageLicenses` in `LicenseCatalog.cs`;
- a whole vendor family → add a `PrefixMap` entry (before any shorter prefix that would also match);
- a proprietary licence recognisable from its text → add a fingerprint to `SpdxTextMatcher.cs`.

Entries a same-value prefix already covers are removed on sight — the database only holds what a prefix cannot.

## Architecture

[`docs/architecture.md`](docs/architecture.md) explains how the code is organised, how each check works, and the design decisions behind them.
