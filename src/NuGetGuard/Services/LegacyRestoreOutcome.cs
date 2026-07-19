namespace NuGetGuard.Services;

public enum LegacyRestoreOutcome
{
    NoLegacyProjects,
    NuGetExeUnavailable,
    NoPackagesFolder,
    Restored,
}
