using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

internal sealed class DependencyGroup
{
    [JsonPropertyName("targetFramework")] public string? TargetFramework { get; set; }
    [JsonPropertyName("dependencies")] public List<PackageDependency>? Dependencies { get; set; }
}
