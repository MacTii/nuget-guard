using NuGet.Versioning;
using NuGetGuard.Models;
using NuGetGuard.Services.ClearlyDefined;
using NuGetGuard.Services.DotNet;
using NuGetGuard.Services.DotNet.Models;
using NuGetGuard.Services.NuGetApi;

namespace NuGetGuard.Services;

/// <summary>
/// Builds the individual sections of a <see cref="ScanReport"/>.
/// Pure application logic — no console I/O; progress/info is surfaced via callbacks.
/// </summary>
public sealed class ReportBuilder(NuGetClient nuget)
{
    /// <summary>Fetches NuGet metadata for all collected packages in parallel.</summary>
    public async Task<List<PackageMetadata>> FetchMetadataAsync(
        IReadOnlyCollection<CollectedPackage> packages,
        Action? onPackageDone = null,
        CancellationToken ct = default)
    {
        var results = new List<PackageMetadata>(packages.Count);
        var gate = new object();

        await Parallel.ForEachAsync(
            packages,
            new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
            async (package, token) =>
            {
                var metadata = await nuget.GetMetadataAsync(package, token);
                lock (gate) { results.Add(metadata); }
                onPackageDone?.Invoke();
            });

        results.Sort((a, b) => string.Compare(a.Id, b.Id, StringComparison.OrdinalIgnoreCase));
        return results;
    }

    /// <summary>
    /// Second pass for licences the API did not identify. Everything offline is tried first —
    /// the known-package database, then the licence file the package ships — so the network is
    /// only used for what is left. When <paramref name="clearlyDefined"/> is supplied, its API
    /// is queried for whatever still remains before falling back to scraping the licence page.
    /// </summary>
    public static async Task<int> ResolveRemainingLicensesAsync(
        List<PackageMetadata> metadata,
        LicenseUrlResolver resolver,
        string? legacyPackagesFolder = null,
        ClearlyDefinedClient? clearlyDefined = null,
        CancellationToken ct = default)
    {
        var unresolved = metadata.Where(m => m.License == "Unknown").ToList();
        if (unresolved.Count == 0)
            return 0;

        foreach (var meta in unresolved)
        {
            // The licence file ships inside this exact version, so it outranks the curated
            // database, which can only be keyed by package id. Packages do change their terms
            // between versions — FluentAssertions 8 and MediatR 14 both went commercial.
            var known = PackageLicenseFileReader.Read(meta.Id, meta.Version, legacyPackagesFolder)
                ?? LicenseCatalog.GetKnownLicense(meta.Id);

            if (known is not null)
                meta.License = known;
        }

        if (clearlyDefined is not null)
            await ResolveWithAsync(Still(unresolved), ct,
                (meta, token) => clearlyDefined.GetLicenseAsync(meta.Id, meta.Version, token));

        await ResolveWithAsync(
            Still(unresolved).Where(m => !string.IsNullOrEmpty(m.LicenseUrl)).ToList(), ct,
            (meta, token) => resolver.ResolveFromContentAsync(meta.LicenseUrl, token));

        return unresolved.Count(m => m.License != "Unknown");
    }

    private static List<PackageMetadata> Still(IEnumerable<PackageMetadata> packages) =>
        packages.Where(m => m.License == "Unknown").ToList();

    private static async Task ResolveWithAsync(
        List<PackageMetadata> packages,
        CancellationToken ct,
        Func<PackageMetadata, CancellationToken, Task<string?>> resolve)
    {
        if (packages.Count == 0)
            return;

        await Parallel.ForEachAsync(
            packages,
            new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
            async (meta, token) =>
            {
                var resolved = await resolve(meta, token);
                if (resolved is not null)
                    meta.License = resolved;
            });
    }

    /// <summary>Vulnerable packages: solution-level dotnet scan with per-project fallback, merged with registration API data.</summary>
    public static async Task<(List<ReportItem> Items, List<string> SkippedProjects)> BuildVulnerableAsync(
        SolutionContext solution,
        IReadOnlyList<PackageMetadata> metadata,
        Action<string>? onInfo = null,
        CancellationToken ct = default)
    {
        var map = new Dictionary<string, ReportItem>(StringComparer.OrdinalIgnoreCase);
        var skipped = new List<string>();
        var workingDir = solution.SolutionFile.DirectoryName!;

        var result = await DotNetCli.ListPackagesAsync(
            solution.SolutionFile.FullName, workingDir,
            ["--vulnerable", "--include-transitive"], ct);

        if (result.HasError && result.Report is null)
        {
            onInfo?.Invoke("Solution-level vulnerable scan failed, falling back to per-project...");

            foreach (var project in solution.ProjectFiles)
            {
                var perProject = await DotNetCli.ListPackagesAsync(
                    project.FullName, workingDir, ["--vulnerable", "--include-transitive"], ct);

                if (perProject.HasError && perProject.Report is null)
                {
                    skipped.Add(Path.GetFileNameWithoutExtension(project.Name));
                    continue;
                }
                if (perProject.Report is not null)
                    CollectVulnerable(perProject.Report, map);
            }
        }
        else if (result.Report is not null)
        {
            CollectVulnerable(result.Report, map);
        }

        MergeRegistrationVulnerabilities(metadata, map);

        var items = map.Values.OrderBy(i => Rankings.SeverityOrder(i.Severity)).ToList();
        return (items, skipped);
    }

    public static List<ReportItem> BuildDeprecated(IReadOnlyList<PackageMetadata> metadata)
    {
        var items = new List<ReportItem>();
        foreach (var meta in metadata.Where(m => m.IsDeprecated))
        {
            var item = new ReportItem
            {
                Category = "Deprecated",
                Package = meta.Id,
                Version = meta.Version,
                Severity = meta.DeprecationReasons,
                Message = meta.DeprecationMessage,
                Alternative = meta.AlternativeId is not null
                    ? $"{meta.AlternativeId} {meta.AlternativeRange}".Trim()
                    : null,
            };
            item.AddProjects(meta.Projects);
            items.Add(item);
        }
        return items.OrderBy(i => Rankings.SeverityOrder(i.Severity)).ToList();
    }

    public async Task<(List<ReportItem> Items, bool Failed)> BuildOutdatedAsync(
        SolutionContext solution, CancellationToken ct = default)
    {
        var result = await DotNetCli.ListPackagesAsync(
            solution.SolutionFile.FullName, solution.SolutionFile.DirectoryName!, ["--outdated"], ct);

        var map = new Dictionary<string, ReportItem>(StringComparer.OrdinalIgnoreCase);

        if (result.Report is not null)
            CollectOutdated(result.Report, map);

        // dotnet list cannot analyze packages.config projects — check those against the NuGet API
        await AddLegacyOutdatedAsync(solution, map, ct);

        var failed = result.HasError && result.Report is null && map.Count == 0;
        return (map.Values.OrderBy(i => i.Package, StringComparer.OrdinalIgnoreCase).ToList(), failed);
    }

    private static void CollectOutdated(DotnetListReport report, Dictionary<string, ReportItem> map)
    {
        foreach (var project in report.Projects)
        {
            var projectName = Path.GetFileNameWithoutExtension(project.Path ?? "");

            foreach (var framework in project.Frameworks ?? [])
            {
                foreach (var package in framework.TopLevelPackages ?? [])
                {
                    if (string.IsNullOrEmpty(package.LatestVersion) || package.ResolvedVersion == package.LatestVersion)
                        continue;

                    var key = $"{package.Id}|{package.ResolvedVersion}";
                    if (!map.TryGetValue(key, out var entry))
                    {
                        entry = new ReportItem
                        {
                            Category = "Outdated",
                            Package = package.Id ?? "",
                            Version = package.ResolvedVersion ?? "",
                            Severity = $"Latest: {package.LatestVersion}",
                        };
                        map[key] = entry;
                    }
                    entry.AddProjects([projectName]);
                }
            }
        }

    }

    private async Task AddLegacyOutdatedAsync(
        SolutionContext solution, Dictionary<string, ReportItem> map, CancellationToken ct)
    {
        foreach (var project in solution.ProjectFiles.Where(ProjectFileReader.IsLegacyProject))
        {
            var projectName = Path.GetFileNameWithoutExtension(project.Name);

            foreach (var (id, version) in ProjectFileReader.ReadDirectPackages(project.FullName))
            {
                var latest = await nuget.GetLatestStableVersionAsync(id, ct);
                if (latest is null
                    || !NuGetVersion.TryParse(version, out var current)
                    || !NuGetVersion.TryParse(latest, out var newest)
                    || newest <= current)
                    continue;

                var key = $"{id}|{version}";
                if (!map.TryGetValue(key, out var entry))
                {
                    entry = new ReportItem
                    {
                        Category = "Outdated",
                        Package = id,
                        Version = version,
                        Severity = $"Latest: {latest}",
                    };
                    map[key] = entry;
                }
                entry.AddProjects([projectName]);
            }
        }
    }

    public static List<LicenseItem> BuildLicenses(IReadOnlyList<PackageMetadata> metadata) =>
        metadata
            .Select(m => new LicenseItem(
                m.Id,
                m.Version,
                m.License,
                LicenseCatalog.GetRisk(m.License),
                m.LicenseUrl,
                string.Join(", ", m.Projects)))
            .OrderBy(l => (int)l.Risk)
            .ThenBy(l => l.Package, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static void CollectVulnerable(DotnetListReport report, Dictionary<string, ReportItem> map)
    {
        foreach (var project in report.Projects)
        {
            var projectName = Path.GetFileNameWithoutExtension(project.Path ?? "");

            foreach (var framework in project.Frameworks ?? [])
            {
                var allPackages = (framework.TopLevelPackages ?? []).Concat(framework.TransitivePackages ?? []);

                foreach (var package in allPackages)
                {
                    foreach (var vulnerability in package.Vulnerabilities ?? [])
                    {
                        var severity = Rankings.ToTitleCase(vulnerability.Severity);
                        var entry = GetOrAddVulnerableEntry(
                            map, package.Id ?? "", package.ResolvedVersion ?? "", severity, vulnerability.AdvisoryUrl);
                        entry.AddProjects([projectName]);
                    }
                }
            }
        }
    }

    private static void MergeRegistrationVulnerabilities(
        IReadOnlyList<PackageMetadata> metadata, Dictionary<string, ReportItem> map)
    {
        foreach (var meta in metadata)
        {
            foreach (var vulnerability in meta.Vulnerabilities)
            {
                var severity = Rankings.ToTitleCase(vulnerability.Severity);
                var entry = GetOrAddVulnerableEntry(map, meta.Id, meta.Version, severity, vulnerability.AdvisoryUrl);
                entry.AddProjects(meta.Projects);
            }
        }
    }

    private static ReportItem GetOrAddVulnerableEntry(
        Dictionary<string, ReportItem> map, string package, string version, string severity, string? advisory)
    {
        var key = $"{package}|{version}|{severity}";
        if (!map.TryGetValue(key, out var entry))
        {
            entry = new ReportItem
            {
                Category = "Vulnerable",
                Package = package,
                Version = version,
                Severity = severity,
                Advisory = advisory,
            };
            map[key] = entry;
        }
        return entry;
    }
}
