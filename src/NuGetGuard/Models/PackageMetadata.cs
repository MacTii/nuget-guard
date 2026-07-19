namespace NuGetGuard.Models;

/// <summary>Metadata fetched from the NuGet registration API for a single package version.</summary>
public sealed class PackageMetadata
{
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required IReadOnlyCollection<string> Projects { get; init; }

    public bool IsDeprecated { get; set; }
    public string? DeprecationReasons { get; set; }
    public string? DeprecationMessage { get; set; }
    public string? AlternativeId { get; set; }
    public string? AlternativeRange { get; set; }
    public List<VulnerabilityInfo> Vulnerabilities { get; } = [];
    public string License { get; set; } = "Unknown";
    public string? LicenseUrl { get; set; }
}
