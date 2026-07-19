namespace NuGetGuard.Models;

/// <summary>Aggregated result of the whole scan.</summary>
public sealed class ScanReport
{
    public required string SolutionName { get; init; }
    public List<ReportItem> Vulnerable { get; init; } = [];
    public List<ReportItem> Deprecated { get; init; } = [];
    public List<ReportItem> Outdated { get; init; } = [];
    public bool OutdatedScanFailed { get; init; }
    public List<LicenseItem> Licenses { get; init; } = [];
    public List<RedundantProjectGroup> Redundant { get; init; } = [];
    public List<string> SkippedProjects { get; init; } = [];

    public int StrongCopyleftCount => Licenses.Count(l => l.Risk == LicenseRisk.StrongCopyleft);
    public int UnknownLicenseCount => Licenses.Count(l => l.Risk == LicenseRisk.Unknown);
}
