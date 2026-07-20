using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

internal sealed class DependencyGroup
{
    [JsonPropertyName("dependencies")] public List<PackageDependency>? Dependencies { get; set; }
}
