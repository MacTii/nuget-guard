using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi;

internal sealed class CatalogEntry
{
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("deprecation")] public DeprecationInfo? Deprecation { get; set; }
    [JsonPropertyName("vulnerabilities")] public List<RegistrationVulnerability>? Vulnerabilities { get; set; }
    [JsonPropertyName("licenseExpression")] public string? LicenseExpression { get; set; }
    [JsonPropertyName("licenseUrl")] public string? LicenseUrl { get; set; }
    [JsonPropertyName("dependencyGroups")] public List<DependencyGroup>? DependencyGroups { get; set; }
}
