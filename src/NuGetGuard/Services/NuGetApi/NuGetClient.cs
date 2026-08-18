using NuGet.Versioning;
using NuGetGuard.Models;
using NuGetGuard.Services.Licensing;
using NuGetGuard.Services.NuGetApi.Models;
using NuGetGuard.Services;
using System.Collections.Concurrent;
using System.Text.Json;

namespace NuGetGuard.Services.NuGetApi;

/// <summary>Queries the NuGet registration API for deprecation, vulnerability, license and dependency data.</summary>
public sealed class NuGetClient(HttpClient http)
{
    private const string RegistrationBase = "https://api.nuget.org/v3/registration5-gz-semver2";

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly ConcurrentDictionary<string, Task<RegistrationIndex?>> _indexCache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task<IReadOnlyList<DependencyRef>>> _dependencyCache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task<string?>> _latestVersionCache =
        new(StringComparer.OrdinalIgnoreCase);

    public async Task<PackageMetadata> GetMetadataAsync(CollectedPackage package, CancellationToken ct = default)
    {
        var metadata = new PackageMetadata
        {
            Id = package.Id,
            Version = package.Version,
            Projects = package.Projects.ToList(),
        };

        var entry = await GetCatalogEntryAsync(package.Id, package.Version, ct);
        if (entry is null)
            return metadata;

        ApplyDeprecation(metadata, entry);
        ApplyVulnerabilities(metadata, entry);
        ApplyLicense(metadata, entry, package.Id);
        return metadata;
    }

    public Task<IReadOnlyList<DependencyRef>> GetDependenciesAsync(string id, string version, CancellationToken ct = default)
    {
        return _dependencyCache.GetOrAdd($"{id}|{version}", _ => FetchAsync());

        async Task<IReadOnlyList<DependencyRef>> FetchAsync()
        {
            var entry = await GetCatalogEntryAsync(id, version, ct);
            if (entry?.DependencyGroups is null)
                return [];

            return entry.DependencyGroups
                .SelectMany(g => g.Dependencies ?? [])
                .Where(d => !string.IsNullOrEmpty(d.Id))
                .GroupBy(d => d.Id!, StringComparer.OrdinalIgnoreCase)
                .Select(g => new DependencyRef(g.Key, g.First().Range))
                .OrderBy(d => d.Id, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    /// <summary>Latest stable (non-prerelease) version of a package, or null if unavailable.</summary>
    public Task<string?> GetLatestStableVersionAsync(string id, CancellationToken ct = default)
    {
        return _latestVersionCache.GetOrAdd(id, _ => FetchAsync());

        async Task<string?> FetchAsync()
        {
            var index = await GetJsonAsync<FlatContainerIndex>(
                $"https://api.nuget.org/v3-flatcontainer/{id.ToLowerInvariant()}/index.json", ct);
            if (index?.Versions is not { Count: > 0 })
                return null;

            NuGetVersion? best = null;
            foreach (var raw in index.Versions)
            {
                if (NuGetVersion.TryParse(raw, out var version) && !version.IsPrerelease
                    && (best is null || version > best))
                    best = version;
            }
            return best?.ToString();
        }
    }

    private static void ApplyDeprecation(PackageMetadata metadata, CatalogEntry entry)
    {
        if (entry.Deprecation is null)
            return;

        metadata.IsDeprecated = true;
        metadata.DeprecationReasons = entry.Deprecation.Reasons is { Count: > 0 }
            ? string.Join(", ", entry.Deprecation.Reasons)
            : null;
        metadata.DeprecationMessage = entry.Deprecation.Message;
        metadata.AlternativeId = entry.Deprecation.AlternatePackage?.Id;
        metadata.AlternativeRange = entry.Deprecation.AlternatePackage?.Range;
    }

    private static void ApplyVulnerabilities(PackageMetadata metadata, CatalogEntry entry)
    {
        foreach (var vulnerability in entry.Vulnerabilities ?? [])
        {
            var label = int.TryParse(vulnerability.Severity, out var value)
                ? Rankings.SeverityLabel(value)
                : (vulnerability.Severity ?? "Unknown");
            metadata.Vulnerabilities.Add(new VulnerabilityInfo(label, vulnerability.AdvisoryUrl));
        }
    }

    private static void ApplyLicense(PackageMetadata metadata, CatalogEntry entry, string packageId)
    {
        // 1. SPDX expression directly in catalogEntry
        if (!string.IsNullOrWhiteSpace(entry.LicenseExpression))
        {
            metadata.License = entry.LicenseExpression.Trim();
            metadata.LicenseUrl = entry.LicenseUrl;
        }
        // 2. Derive from licenseUrl pattern. The licence file shipped in the package, the
        //    curated database and the page content are all tried in a later pass — the
        //    database must not run here, because it is keyed by package id and would hide
        //    the version-specific licence file of a package that changed its terms.
        else if (!string.IsNullOrEmpty(entry.LicenseUrl))
        {
            metadata.LicenseUrl = entry.LicenseUrl;
            if (LicenseUrlResolver.ResolveFromUrlPattern(entry.LicenseUrl) is { } fromUrl)
                metadata.License = fromUrl;
        }
    }

    private async Task<CatalogEntry?> GetCatalogEntryAsync(string id, string version, CancellationToken ct)
    {
        var index = await _indexCache.GetOrAdd(id, key => FetchIndexAsync(key, ct));
        if (index?.Items is null)
            return null;

        NuGetVersion.TryParse(version, out var target);

        foreach (var page in index.Items)
        {
            if (target is not null && !PageMayContain(page, target))
                continue;

            var leaves = page.Items;
            if (leaves is null && page.Url is not null)
            {
                var pageData = await GetJsonAsync<RegistrationPage>(page.Url, ct);
                leaves = pageData?.Items;
            }
            if (leaves is null)
                continue;

            foreach (var leaf in leaves)
            {
                if (leaf.CatalogEntry?.Version is null)
                    continue;
                if (VersionsEqual(leaf.CatalogEntry.Version, version, target))
                    return leaf.CatalogEntry;
            }
        }

        return null;
    }

    private static bool PageMayContain(RegistrationPage page, NuGetVersion target)
    {
        if (NuGetVersion.TryParse(page.Lower, out var lower) && target < lower)
            return false;
        if (NuGetVersion.TryParse(page.Upper, out var upper) && target > upper)
            return false;
        return true;
    }

    private static bool VersionsEqual(string candidate, string requested, NuGetVersion? requestedParsed)
    {
        if (string.Equals(candidate, requested, StringComparison.OrdinalIgnoreCase))
            return true;
        return requestedParsed is not null
            && NuGetVersion.TryParse(candidate, out var parsed)
            && parsed == requestedParsed;
    }

    private async Task<RegistrationIndex?> FetchIndexAsync(string id, CancellationToken ct) =>
        await GetJsonAsync<RegistrationIndex>($"{RegistrationBase}/{id.ToLowerInvariant()}/index.json", ct);

    private async Task<T?> GetJsonAsync<T>(string url, CancellationToken ct) where T : class
    {
        try
        {
            await using var stream = await http.GetStreamAsync(url, ct);
            return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, ct);
        }
        catch
        {
            return null; // package not on nuget.org, network error, etc. — non-fatal
        }
    }
}
