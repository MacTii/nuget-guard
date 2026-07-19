using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

/// <summary>Root of a NuGet registration index (per package id).</summary>
internal sealed class RegistrationIndex
{
    [JsonPropertyName("items")] public List<RegistrationPage>? Items { get; set; }
}
