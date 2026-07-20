using System.Xml.Linq;

namespace NuGetGuard.Services;

/// <summary>Reads MSBuild project files: package references, project type and project references.</summary>
public static class ProjectFileReader
{
    /// <summary>Direct packages of a single project: PackageReference (attribute or child element) + packages.config.</summary>
    public static Dictionary<string, string> ReadDirectPackages(
        string projectPath,
        IReadOnlyDictionary<string, string>? centralVersions = null)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(projectPath))
            return result;

        XDocument xml;
        try { xml = XDocument.Load(projectPath); }
        catch { return result; }

        foreach (var reference in xml.Descendants().Where(e => e.Name.LocalName == "PackageReference"))
        {
            var id = (string?)reference.Attribute("Include") ?? (string?)reference.Attribute("Update");
            if (string.IsNullOrEmpty(id))
                continue;

            var version = (string?)reference.Attribute("Version")
                ?? reference.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value;

            if (string.IsNullOrEmpty(version) && centralVersions is not null)
                centralVersions.TryGetValue(id, out version);

            if (string.IsNullOrEmpty(version) || version.Contains('*'))
                continue;

            result[id] = version;
        }

        var configPath = Path.Combine(Path.GetDirectoryName(projectPath)!, "packages.config");
        if (File.Exists(configPath))
        {
            try
            {
                var config = XDocument.Load(configPath);
                foreach (var package in config.Descendants().Where(e => e.Name.LocalName == "package"))
                {
                    var id = (string?)package.Attribute("id");
                    var version = (string?)package.Attribute("version");
                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(version))
                        result[id] = version;
                }
            }
            catch { /* malformed packages.config — skip */ }
        }

        return result;
    }

    /// <summary>Central Package Management: Directory.Packages.props → PackageVersion map.</summary>
    public static Dictionary<string, string> ReadCentralPackageVersions(string solutionDir)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var propsPath = Path.Combine(solutionDir, "Directory.Packages.props");
        if (!File.Exists(propsPath))
            return result;

        try
        {
            var xml = XDocument.Load(propsPath);
            foreach (var entry in xml.Descendants().Where(e => e.Name.LocalName == "PackageVersion"))
            {
                var id = (string?)entry.Attribute("Include");
                var version = (string?)entry.Attribute("Version");
                if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(version) && !version.Contains('*'))
                    result[id] = version;
            }
        }
        catch { /* malformed props file — treat as no CPM */ }

        return result;
    }

    public static bool IsLegacyProject(FileInfo project) =>
        File.Exists(Path.Combine(project.DirectoryName!, "packages.config"));

    public static bool IsSdkStyleProject(FileInfo project)
    {
        try
        {
            var xml = XDocument.Load(project.FullName);
            return !string.IsNullOrEmpty((string?)xml.Root?.Attribute("Sdk"));
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// File paths explicitly listed in the project (Compile/Content/None items), resolved to absolute paths.
    /// Legacy projects enumerate every file, and both formats use this for linked files living outside
    /// the project folder.
    /// </summary>
    public static IEnumerable<string> GetIncludedFilePaths(string projectPath)
    {
        if (!File.Exists(projectPath))
            yield break;

        XDocument xml;
        try { xml = XDocument.Load(projectPath); }
        catch { yield break; }

        var projectDir = Path.GetDirectoryName(Path.GetFullPath(projectPath))!;

        foreach (var item in xml.Descendants())
        {
            if (item.Name.LocalName is not ("Compile" or "Content" or "None"))
                continue;

            var include = (string?)item.Attribute("Include");
            if (string.IsNullOrEmpty(include) || include.Contains('*'))
                continue;

            string resolved;
            try
            {
                resolved = Path.GetFullPath(
                    Path.Combine(projectDir, include.Replace('\\', Path.DirectorySeparatorChar)));
            }
            catch (ArgumentException)
            {
                continue; // invalid path characters in the item
            }

            if (File.Exists(resolved))
                yield return resolved;
        }
    }

    /// <summary>Recursively collects all ProjectReference paths reachable from a project (excluding itself).</summary>
    public static HashSet<string> GetProjectReferenceClosure(string projectPath)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Visit(projectPath, visited);
        visited.Remove(Path.GetFullPath(projectPath));
        return visited;

        static void Visit(string path, HashSet<string> visited)
        {
            if (!File.Exists(path))
                return;
            var fullPath = Path.GetFullPath(path);
            if (!visited.Add(fullPath))
                return;

            XDocument xml;
            try { xml = XDocument.Load(fullPath); }
            catch { return; }

            var projectDir = Path.GetDirectoryName(fullPath)!;
            foreach (var reference in xml.Descendants().Where(e => e.Name.LocalName == "ProjectReference"))
            {
                var include = (string?)reference.Attribute("Include");
                if (string.IsNullOrEmpty(include))
                    continue;

                var resolvedPath = Path.GetFullPath(Path.Combine(projectDir, include.Replace('\\', Path.DirectorySeparatorChar)));
                if (File.Exists(resolvedPath))
                    Visit(resolvedPath, visited);
            }
        }
    }
}
