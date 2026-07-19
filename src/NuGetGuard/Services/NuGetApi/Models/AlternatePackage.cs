using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

internal sealed class AlternatePackage
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("range")] public string? Range { get; set; }
}
