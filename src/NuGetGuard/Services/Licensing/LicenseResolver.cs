using NuGetGuard.Models;
using NuGetGuard.Services.Licensing.ClearlyDefined;

namespace NuGetGuard.Services.Licensing;

/// <summary>
/// Second pass for licences the NuGet API did not identify, and the licence section of the report.
/// Everything offline is tried first, so the network is only used for what is left.
/// </summary>
public static class LicenseResolver
{
    public static async Task<int> ResolveRemainingAsync(
        List<PackageMetadata> metadata,
        LicenseUrlResolver resolver,
        string? legacyPackagesFolder = null,
        ClearlyDefinedClient? clearlyDefined = null,
        CancellationToken ct = default)
    {
        var unresolved = metadata.Where(m => m.License == "Unknown").ToList();
        if (unresolved.Count == 0)
            return 0;

        foreach (var meta in unresolved)
        {
            // The licence file ships inside this exact version, so it outranks the curated
            // database, which can only be keyed by package id. Packages do change their terms
            // between versions — FluentAssertions 8 and MediatR 14 both went commercial.
            var known = PackageLicenseFileReader.Read(meta.Id, meta.Version, legacyPackagesFolder)
                ?? LicenseCatalog.GetKnownLicense(meta.Id);

            if (known is not null)
                meta.License = known;
        }

        if (clearlyDefined is not null)
            await ResolveWithAsync(Still(unresolved), ct,
                (meta, token) => clearlyDefined.GetLicenseAsync(meta.Id, meta.Version, token));

        await ResolveWithAsync(
            Still(unresolved).Where(m => !string.IsNullOrEmpty(m.LicenseUrl)).ToList(), ct,
            (meta, token) => resolver.ResolveFromContentAsync(meta.LicenseUrl, token));

        return unresolved.Count(m => m.License != "Unknown");
    }

    /// <summary>One row per package, worst risk first.</summary>
    public static List<LicenseItem> BuildItems(IReadOnlyList<PackageMetadata> metadata) =>
        metadata
            .Select(m => new LicenseItem(
                m.Id,
                m.Version,
                m.License,
                LicenseCatalog.GetRisk(m.License),
                m.LicenseUrl,
                string.Join(", ", m.Projects)))
            .OrderBy(l => (int)l.Risk)
            .ThenBy(l => l.Package, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static List<PackageMetadata> Still(IEnumerable<PackageMetadata> packages) =>
        packages.Where(m => m.License == "Unknown").ToList();

    private static async Task ResolveWithAsync(
        List<PackageMetadata> packages,
        CancellationToken ct,
        Func<PackageMetadata, CancellationToken, Task<string?>> resolve)
    {
        if (packages.Count == 0)
            return;

        await Parallel.ForEachAsync(
            packages,
            new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
            async (meta, token) =>
            {
                var resolved = await resolve(meta, token);
                if (resolved is not null)
                    meta.License = resolved;
            });
    }
}
