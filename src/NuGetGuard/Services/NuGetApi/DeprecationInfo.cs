using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi;

internal sealed class DeprecationInfo
{
    [JsonPropertyName("reasons")] public List<string>? Reasons { get; set; }
    [JsonPropertyName("message")] public string? Message { get; set; }
    [JsonPropertyName("alternatePackage")] public AlternatePackage? AlternatePackage { get; set; }
}
