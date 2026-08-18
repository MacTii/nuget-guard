using NuGetGuard.Models;

namespace NuGetGuard.Services.Discovery;

/// <summary>Aggregates direct package references from all projects into a solution-wide bag.</summary>
public static class PackageCollector
{
    /// <summary>Collects all direct package references from every project into a bag keyed by "Id|Version".</summary>
    public static Dictionary<string, CollectedPackage> CollectPackages(SolutionContext context)
    {
        var bag = new Dictionary<string, CollectedPackage>(StringComparer.OrdinalIgnoreCase);
        var centralVersions = ProjectFileReader.ReadCentralPackageVersions(context.SolutionFile.DirectoryName!);

        foreach (var project in context.ProjectFiles)
        {
            var projectName = Path.GetFileNameWithoutExtension(project.Name);
            foreach (var (id, version) in ProjectFileReader.ReadDirectPackages(project.FullName, centralVersions))
                Add(bag, id, version, projectName);
        }

        return bag;
    }

    public static void Add(Dictionary<string, CollectedPackage> bag, string? id, string? version, string projectName)
    {
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(version))
            return;

        var key = $"{id}|{version}";
        if (!bag.TryGetValue(key, out var package))
        {
            package = new CollectedPackage { Id = id, Version = version };
            bag[key] = package;
        }
        package.Projects.Add(projectName);
    }

}
