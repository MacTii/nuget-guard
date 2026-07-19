namespace NuGetGuard.Models;

public sealed record LicenseItem(
    string Package,
    string Version,
    string License,
    LicenseRisk Risk,
    string? LicenseUrl,
    string Projects);
