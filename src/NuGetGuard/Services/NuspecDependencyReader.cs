using System.Xml.Linq;

namespace NuGetGuard.Services;

/// <summary>Reads dependency ids from the .nuspec of a package restored into the legacy packages/ folder.</summary>
public static class NuspecDependencyReader
{
    /// <summary>
    /// Dependencies declared by a restored package. Empty when there is no legacy packages folder,
    /// the package is not restored there, or its .nuspec cannot be read.
    /// </summary>
    public static IReadOnlyList<string> ReadDependencyIds(string? packagesFolder, string id, string version)
    {
        if (packagesFolder is null)
            return [];

        var packageDir = Path.Combine(packagesFolder, $"{id}.{version}");
        if (!Directory.Exists(packageDir))
            return [];

        var nuspec = Directory.EnumerateFiles(packageDir, "*.nuspec", SearchOption.AllDirectories).FirstOrDefault();
        return nuspec is null ? [] : ReadDependencyIds(nuspec);
    }

    private static List<string> ReadDependencyIds(string nuspecPath)
    {
        var deps = new List<string>();
        XDocument nuspec;
        try { nuspec = XDocument.Load(nuspecPath); }
        catch { return deps; }

        var groups = nuspec.Descendants().Where(e => e.Name.LocalName == "group").ToList();

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

            if (bestGroup is not null)
            {
                deps.AddRange(bestGroup.Elements()
                    .Where(e => e.Name.LocalName == "dependency")
                    .Select(e => (string?)e.Attribute("id"))
                    .Where(depId => !string.IsNullOrEmpty(depId))!);
            }
        }
        else
        {
            deps.AddRange(nuspec.Descendants()
                .Where(e => e.Name.LocalName == "dependency")
                .Select(e => (string?)e.Attribute("id"))
                .Where(depId => !string.IsNullOrEmpty(depId))!);
        }

        return deps.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
