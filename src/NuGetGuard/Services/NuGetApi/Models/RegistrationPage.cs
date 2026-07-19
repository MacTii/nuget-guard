using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

internal sealed class RegistrationPage
{
    [JsonPropertyName("@id")] public string? Url { get; set; }
    [JsonPropertyName("lower")] public string? Lower { get; set; }
    [JsonPropertyName("upper")] public string? Upper { get; set; }
    [JsonPropertyName("items")] public List<RegistrationLeaf>? Items { get; set; }
}
