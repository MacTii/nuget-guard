namespace NuGetGuard.Infrastructure.Packages;

public enum LegacyRestoreOutcome
{
    NoLegacyProjects,
    NuGetExeUnavailable,
    NoPackagesFolder,
    Restored,
}
