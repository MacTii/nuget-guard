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
    public List<UnusedProjectGroup> Unused { get; init; } = [];
    public List<string> SkippedProjects { get; init; } = [];

    /// <summary>Set when the analysis was switched off, so "none found" is never shown for a check that never ran.</summary>
    public bool RedundantSkipped { get; init; }
    public bool UnusedSkipped { get; init; }

    public int StrongCopyleftCount => Licenses.Count(l => l.Risk == LicenseRisk.StrongCopyleft);
    public int ProprietaryLicenseCount => Licenses.Count(l => l.Risk == LicenseRisk.Proprietary);
    public int UnknownLicenseCount => Licenses.Count(l => l.Risk == LicenseRisk.Unknown);
    public int UnusedCount => Unused.Sum(g => g.Items.Count);
    public int RedundantCount => Redundant.Sum(g => g.Items.Count);
}
