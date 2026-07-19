using System.Text.Json.Serialization;

namespace NuGetGuard.Services.DotNet.Models;

/// <summary>Root of the `dotnet list package --format json` output.</summary>
public sealed class DotnetListReport
{
    [JsonPropertyName("projects")] public List<DotnetProject> Projects { get; set; } = [];
}
