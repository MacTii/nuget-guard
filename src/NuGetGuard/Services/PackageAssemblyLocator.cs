namespace NuGetGuard.Services;

/// <summary>Finds the assemblies shipped by an installed package, in the global or the legacy packages folder.</summary>
public static class PackageAssemblyLocator
{
    private static readonly string[] AssemblyFolders = ["lib", "ref"];

    /// <summary>
    /// Assemblies shipped in the package's lib/ (or ref/) folder.
    /// Empty when the package ships no assemblies (analyzers, MSBuild targets, static content)
    /// or when it is not restored on this machine.
    /// </summary>
    public static IReadOnlyList<string> FindAssemblies(string id, string version, string? legacyPackagesFolder)
    {
        foreach (var root in CandidateRoots(id, version, legacyPackagesFolder))
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var folder in AssemblyFolders)
            {
                var path = Path.Combine(root, folder);
                if (!Directory.Exists(path))
                    continue;

                var assemblies = Directory.EnumerateFiles(path, "*.dll", SearchOption.AllDirectories).ToList();
                if (assemblies.Count > 0)
                    return assemblies;
            }
        }

        return [];
    }

    private static IEnumerable<string> CandidateRoots(string id, string version, string? legacyPackagesFolder)
    {
        yield return Path.Combine(GlobalPackagesFolder(), id.ToLowerInvariant(), version.ToLowerInvariant());

        if (legacyPackagesFolder is not null)
            yield return Path.Combine(legacyPackagesFolder, $"{id}.{version}");
    }

    private static string GlobalPackagesFolder() =>
        Environment.GetEnvironmentVariable("NUGET_PACKAGES")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
}
