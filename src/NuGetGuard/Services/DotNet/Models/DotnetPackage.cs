using System.Text.Json.Serialization;

namespace NuGetGuard.Services.DotNet.Models;

public sealed class DotnetPackage
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("resolvedVersion")] public string? ResolvedVersion { get; set; }
    [JsonPropertyName("latestVersion")] public string? LatestVersion { get; set; }
    [JsonPropertyName("vulnerabilities")] public List<DotnetVulnerability>? Vulnerabilities { get; set; }
}
