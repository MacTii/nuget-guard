using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi;

internal sealed class PackageDependency
{
    [JsonPropertyName("id")] public string? Id { get; set; }
}
