using NuGet.Versioning;
using NuGetGuard.Models;
using NuGetGuard.Services.DotNet;
using NuGetGuard.Services.DotNet.Models;
using NuGetGuard.Services.NuGetApi;

namespace NuGetGuard.Services;

/// <summary>
/// Packages behind their latest stable version. <c>dotnet list</c> covers SDK-style projects;
/// packages.config projects it cannot read are checked against the NuGet API instead.
/// </summary>
public sealed class OutdatedReport(NuGetClient nuget)
{
    public async Task<(List<ReportItem> Items, bool Failed)> BuildAsync(
        SolutionContext solution, CancellationToken ct = default)
    {
        var result = await DotNetCli.ListPackagesAsync(
            solution.SolutionFile.FullName, solution.SolutionFile.DirectoryName!, ["--outdated"], ct);

        var map = new Dictionary<string, ReportItem>(StringComparer.OrdinalIgnoreCase);

        if (result.Report is not null)
            Collect(result.Report, map);

        await AddLegacyAsync(solution, map, ct);

        var failed = result.HasError && result.Report is null && map.Count == 0;
        return (map.Values.OrderBy(i => i.Package, StringComparer.OrdinalIgnoreCase).ToList(), failed);
    }

    private static void Collect(DotnetListReport report, Dictionary<string, ReportItem> map)
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

                    Add(map, package.Id ?? "", package.ResolvedVersion ?? "", package.LatestVersion, projectName);
                }
            }
        }
    }

    private async Task AddLegacyAsync(
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

                Add(map, id, version, latest, projectName);
            }
        }
    }

    private static void Add(
        Dictionary<string, ReportItem> map, string id, string version, string latest, string projectName)
    {
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
