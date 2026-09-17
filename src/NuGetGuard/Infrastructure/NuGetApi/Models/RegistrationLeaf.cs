using System.Text.Json.Serialization;

namespace NuGetGuard.Infrastructure.NuGetApi.Models;

internal sealed class RegistrationLeaf
{
    [JsonPropertyName("catalogEntry")] public CatalogEntry? CatalogEntry { get; set; }
}
