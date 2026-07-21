namespace NuGetGuard.Services;

/// <summary>Locates a restored package on disk, in the global cache or in a legacy packages folder.</summary>
public static class PackageFolderLocator
{
    /// <summary>The folders a package could have been restored into, most likely first.</summary>
    public static IEnumerable<string> CandidateRoots(string id, string version, string? legacyPackagesFolder)
    {
        yield return Path.Combine(GlobalPackagesFolder(), id.ToLowerInvariant(), version.ToLowerInvariant());

        if (legacyPackagesFolder is not null)
            yield return Path.Combine(legacyPackagesFolder, $"{id}.{version}");
    }

    /// <summary>The folder the package was restored into, or null when it is not on this machine.</summary>
    public static string? Find(string id, string version, string? legacyPackagesFolder) =>
        CandidateRoots(id, version, legacyPackagesFolder).FirstOrDefault(Directory.Exists);

    private static string GlobalPackagesFolder() =>
        Environment.GetEnvironmentVariable("NUGET_PACKAGES")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
}
