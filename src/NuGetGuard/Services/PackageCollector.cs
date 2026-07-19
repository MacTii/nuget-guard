using System.Text.RegularExpressions;
using NuGetGuard.Models;

namespace NuGetGuard.Services;

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

    /// <summary>Adds packages restored to the legacy packages/ folder (transitive deps of packages.config projects).</summary>
    public static void AddLegacyTransitivePackages(
        IEnumerable<FileInfo> legacyProjects,
        string packagesRoot,
        Dictionary<string, CollectedPackage> bag)
    {
        var folderPattern = new Regex(@"^(?<id>.+?)\.(?<ver>\d+(\.\d+){1,3}(-[\w\.]+)?)$", RegexOptions.Compiled);
        var resolved = Directory.EnumerateDirectories(packagesRoot)
            .Select(Path.GetFileName)
            .Where(name => name is not null)
            .Select(name => folderPattern.Match(name!))
            .Where(m => m.Success)
            .Select(m => (Id: m.Groups["id"].Value, Version: m.Groups["ver"].Value))
            .ToList();

        foreach (var legacy in legacyProjects)
        {
            var projectName = Path.GetFileNameWithoutExtension(legacy.Name);
            foreach (var (id, version) in resolved)
                Add(bag, id, version, projectName);
        }
    }
}
