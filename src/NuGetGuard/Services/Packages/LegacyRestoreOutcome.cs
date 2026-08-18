namespace NuGetGuard.Services.Packages;

public enum LegacyRestoreOutcome
{
    NoLegacyProjects,
    NuGetExeUnavailable,
    NoPackagesFolder,
    Restored,
}
