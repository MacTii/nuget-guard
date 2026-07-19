using System.Text.Json.Serialization;

namespace NuGetGuard.Services.DotNet;

public sealed class DotnetPackage
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("requestedVersion")] public string? RequestedVersion { get; set; }
    [JsonPropertyName("resolvedVersion")] public string? ResolvedVersion { get; set; }
    [JsonPropertyName("latestVersion")] public string? LatestVersion { get; set; }
    [JsonPropertyName("vulnerabilities")] public List<DotnetVulnerability>? Vulnerabilities { get; set; }
}
