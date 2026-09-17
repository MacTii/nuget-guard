namespace NuGetGuard.Checks.Licenses;

public sealed record LicenseItem(
    string Package,
    string Version,
    string License,
    LicenseRisk Risk,
    string? LicenseUrl,
    string Projects);
