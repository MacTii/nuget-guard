using NuGetGuard.Services.DotNet;

namespace NuGetGuard.Services;

/// <summary>
/// Restores legacy packages.config projects via nuget.exe so that the packages/ folder
/// is available for offline dependency and assembly lookups.
///
/// The restored folder is never used as a source of packages: packages.config already lists the
/// full flattened closure, while the folder is solution-wide and keeps versions from earlier
/// restores. Reading packages from it would report packages the projects no longer reference.
/// </summary>
public sealed class LegacyRestorer(HttpClient http)
{
    public static bool HasLegacyProjects(SolutionContext solution) =>
        solution.ProjectFiles.Any(ProjectFileReader.IsLegacyProject);

    public async Task<LegacyRestoreOutcome> RestoreAsync(SolutionContext solution, CancellationToken ct = default)
    {
        if (!HasLegacyProjects(solution))
            return LegacyRestoreOutcome.NoLegacyProjects;

        var nugetExe = await NuGetExe.GetOrDownloadAsync(http, ct);
        if (nugetExe is null)
            return LegacyRestoreOutcome.NuGetExeUnavailable;

        await NuGetExe.RestoreAsync(nugetExe, solution.SolutionFile.FullName, ct);

        return solution.PackagesFolder is null
            ? LegacyRestoreOutcome.NoPackagesFolder
            : LegacyRestoreOutcome.Restored;
    }
}
