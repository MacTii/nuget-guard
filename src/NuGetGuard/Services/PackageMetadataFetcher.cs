using NuGetGuard.Models;
using NuGetGuard.Services.NuGetApi;

namespace NuGetGuard.Services;

/// <summary>Fetches NuGet metadata for the collected packages, in parallel.</summary>
public sealed class PackageMetadataFetcher(NuGetClient nuget)
{
    public async Task<List<PackageMetadata>> FetchAsync(
        IReadOnlyCollection<CollectedPackage> packages,
        Action? onPackageDone = null,
        CancellationToken ct = default)
    {
        var results = new List<PackageMetadata>(packages.Count);
        var gate = new object();

        await Parallel.ForEachAsync(
            packages,
            new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct },
            async (package, token) =>
            {
                var metadata = await nuget.GetMetadataAsync(package, token);
                lock (gate) { results.Add(metadata); }
                onPackageDone?.Invoke();
            });

        results.Sort((a, b) => string.Compare(a.Id, b.Id, StringComparison.OrdinalIgnoreCase));
        return results;
    }
}
