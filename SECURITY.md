# Security

## What NuGetGuard does with your code

The scan is read-only and stays on your machine. NuGetGuard reads project files, `packages.config`, and — for the unused check — your source files and the package assemblies already restored on disk. Assembly inspection is metadata-only: **no package code is ever loaded or executed**, and no build is run.

## What leaves your machine

Only package identities (id + version) are sent, and only to look up public metadata:

- **api.nuget.org** — vulnerabilities, deprecations, licences, latest versions, dependency ranges;
- **api.clearlydefined.io** — licence data, and only with `--online-licenses`;
- a package's own licence URL — only when earlier offline steps could not identify the licence.

No source code, file contents, or project names are transmitted. Nothing is written outside the report file you ask for.

## Reporting a vulnerability

If you find a security issue in NuGetGuard itself, please open a [private security advisory](https://github.com/MacTii/nuget-guard/security/advisories/new) rather than a public issue. You'll get an acknowledgement within a few days.
