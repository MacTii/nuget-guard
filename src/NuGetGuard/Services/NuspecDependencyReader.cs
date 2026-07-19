using System.Xml.Linq;

namespace NuGetGuard.Services;

/// <summary>Reads dependency ids from a local .nuspec file (legacy packages/ folder).</summary>
public static class NuspecDependencyReader
{
    public static List<string> ReadDependencyIds(string nuspecPath)
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
