using System.Text.Json.Serialization;

namespace NuGetGuard.Services.DotNet.Models;

public sealed class DotnetFramework
{
    [JsonPropertyName("topLevelPackages")] public List<DotnetPackage>? TopLevelPackages { get; set; }
    [JsonPropertyName("transitivePackages")] public List<DotnetPackage>? TransitivePackages { get; set; }
}
