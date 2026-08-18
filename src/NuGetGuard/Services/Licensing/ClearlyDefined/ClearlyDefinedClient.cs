using System.Collections.Concurrent;
using System.Text.Json;

namespace NuGetGuard.Services.Licensing.ClearlyDefined;

/// <summary>
/// Resolves a licence from the ClearlyDefined API — an open service that scans package contents
/// and curates the declared licence. Opt-in, because it adds a network call per unresolved
/// package and a scan should stay offline and deterministic by default.
/// </summary>
public sealed class ClearlyDefinedClient(HttpClient http)
{
    private const string Base = "https://api.clearlydefined.io/definitions/nuget/nuget/-";

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly ConcurrentDictionary<string, Task<string?>> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The declared SPDX licence, or null when the service has nothing usable.</summary>
    public Task<string?> GetLicenseAsync(string id, string version, CancellationToken ct = default) =>
        _cache.GetOrAdd($"{id}|{version}", _ => FetchAsync(id, version, ct));

    private async Task<string?> FetchAsync(string id, string version, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));

            await using var stream = await http.GetStreamAsync($"{Base}/{id}/{version}", cts.Token);
            var definition = await JsonSerializer.DeserializeAsync<Definition>(stream, JsonOptions, cts.Token);

            return Clean(definition?.Licensed?.Declared);
        }
        catch
        {
            return null; // service down, timeout, package not harvested — non-fatal
        }
    }

    /// <summary>
    /// Keeps only a usable SPDX expression. ClearlyDefined marks "no usable data" with tokens
    /// such as NOASSERTION, OTHER and LicenseRef-*; those are treated as unresolved so the tool
    /// leaves the package Unknown rather than inventing a licence.
    /// </summary>
    private static string? Clean(string? declared)
    {
        if (string.IsNullOrWhiteSpace(declared))
            return null;

        if (declared.Contains("NOASSERTION", StringComparison.OrdinalIgnoreCase)
            || declared.Contains("OTHER", StringComparison.OrdinalIgnoreCase)
            || declared.Contains("LicenseRef", StringComparison.OrdinalIgnoreCase))
            return null;

        return declared.Trim();
    }

    private sealed class Definition
    {
        public LicensedInfo? Licensed { get; set; }
    }

    private sealed class LicensedInfo
    {
        public string? Declared { get; set; }
    }
}
