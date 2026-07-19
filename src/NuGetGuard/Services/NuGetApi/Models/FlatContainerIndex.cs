using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

/// <summary>Version list from the NuGet flat-container endpoint.</summary>
internal sealed class FlatContainerIndex
{
    [JsonPropertyName("versions")] public List<string>? Versions { get; set; }
}
