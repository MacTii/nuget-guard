using System.Text.Json.Serialization;

namespace NuGetGuard.Services.DotNet;

public sealed class DotnetProject
{
    [JsonPropertyName("path")] public string? Path { get; set; }
    [JsonPropertyName("frameworks")] public List<DotnetFramework>? Frameworks { get; set; }
}
