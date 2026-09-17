using System.Text.Json.Serialization;

namespace NuGetGuard.Infrastructure.NuGetApi.Models;

internal sealed class DeprecationInfo
{
    [JsonPropertyName("reasons")] public List<string>? Reasons { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
    [JsonPropertyName("alternatePackage")] public AlternatePackage? AlternatePackage { get; set; }
}
