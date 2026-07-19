using NuGetGuard.Models;
using NuGetGuard.Services.DotNet;

namespace NuGetGuard.Services;

/// <summary>
/// Restores legacy packages.config projects via nuget.exe and adds
/// their transitive dependencies (from the packages/ folder) to the bag.
/// </summary>
public sealed class LegacyRestorer(HttpClient http)
{
    public static bool HasLegacyProjects(SolutionContext solution) =>
        solution.ProjectFiles.Any(ProjectFileReader.IsLegacyProject);

    public async Task<LegacyRestoreOutcome> RestoreAsync(
        SolutionContext solution,
        Dictionary<string, CollectedPackage> packages,
        CancellationToken ct = default)
    {
        var legacyProjects = solution.ProjectFiles.Where(ProjectFileReader.IsLegacyProject).ToList();
        if (legacyProjects.Count == 0)
            return LegacyRestoreOutcome.NoLegacyProjects;

        var nugetExe = await NuGetExe.GetOrDownloadAsync(http, ct);
        if (nugetExe is null)
            return LegacyRestoreOutcome.NuGetExeUnavailable;

        await NuGetExe.RestoreAsync(nugetExe, solution.SolutionFile.FullName, ct);

        if (solution.PackagesFolder is not { } packagesRoot)
            return LegacyRestoreOutcome.NoPackagesFolder;

        PackageCollector.AddLegacyTransitivePackages(legacyProjects, packagesRoot, packages);
        return LegacyRestoreOutcome.Restored;
    }
}
