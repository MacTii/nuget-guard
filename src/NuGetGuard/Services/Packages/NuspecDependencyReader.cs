using System.Xml.Linq;
using NuGetGuard.Models;

namespace NuGetGuard.Services.Packages;

/// <summary>Reads dependencies from the .nuspec of a package restored into the legacy packages/ folder.</summary>
public static class NuspecDependencyReader
{
    /// <summary>Dependency ids declared by a restored package.</summary>
    public static IReadOnlyList<string> ReadDependencyIds(string? packagesFolder, string id, string version) =>
        ReadDependencies(packagesFolder, id, version).Select(d => d.Id).ToList();

    /// <summary>
    /// Dependencies (id and version range) declared by a restored package. Empty when there is no
    /// legacy packages folder, the package is not restored there, or its .nuspec cannot be read.
    /// </summary>
    public static IReadOnlyList<DependencyRef> ReadDependencies(string? packagesFolder, string id, string version)
    {
        if (packagesFolder is null)
            return [];

        var packageDir = Path.Combine(packagesFolder, $"{id}.{version}");
        if (!Directory.Exists(packageDir))
            return [];

        var nuspec = Directory.EnumerateFiles(packageDir, "*.nuspec", SearchOption.AllDirectories).FirstOrDefault();
        return nuspec is null ? [] : ReadDependencies(nuspec);
    }

    private static List<DependencyRef> ReadDependencies(string nuspecPath)
    {
        var deps = new List<DependencyRef>();
        XDocument nuspec;
        try { nuspec = XDocument.Load(nuspecPath); }
        catch { return deps; }

        var groups = nuspec.Descendants().Where(e => e.Name.LocalName == "group").ToList();

        IEnumerable<XElement> dependencyElements;
        if (groups.Count > 0)
        {
            // Prefer a group without targetFramework, or one matching net4* / netstandard
            var bestGroup = groups.FirstOrDefault(g =>
            {
                var tf = (string?)g.Attribute("targetFramework");
                return string.IsNullOrEmpty(tf)
                    || tf.Contains("net4", StringComparison.OrdinalIgnoreCase)
                    || tf.Contains("netstandard", StringComparison.OrdinalIgnoreCase);
            });

            dependencyElements = bestGroup?.Elements().Where(e => e.Name.LocalName == "dependency") ?? [];
        }
        else
        {
            dependencyElements = nuspec.Descendants().Where(e => e.Name.LocalName == "dependency");
        }

        foreach (var element in dependencyElements)
        {
            var depId = (string?)element.Attribute("id");
            if (!string.IsNullOrEmpty(depId))
                deps.Add(new DependencyRef(depId, (string?)element.Attribute("version")));
        }

        return deps
            .GroupBy(d => d.Id, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
    }
}
