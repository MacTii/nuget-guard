namespace NuGetGuard.Models;

public sealed record RedundantPackage(
    string Package,
    string Version,
    string CoveredBy,
    string CoveredByVersion,
    string CoveredBySource);
