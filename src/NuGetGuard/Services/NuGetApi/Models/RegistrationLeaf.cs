using System.Text.Json.Serialization;

namespace NuGetGuard.Services.NuGetApi.Models;

internal sealed class RegistrationLeaf
{
    [JsonPropertyName("catalogEntry")] public CatalogEntry? CatalogEntry { get; set; }
}
