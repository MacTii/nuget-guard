using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace NuGetGuard.Services.Discovery;

/// <summary>
/// Reads the projects a solution actually contains, so that scanning a folder holding several
/// solutions does not mix unrelated projects into one report.
/// </summary>
public static class SolutionProjectReader
{
    // Project("{type-guid}") = "Name", "relative\path\Project.csproj", "{project-guid}"
    private static readonly Regex SlnProjectLine = new(
        @"^Project\(""\{[^}]+\}""\)\s*=\s*""[^""]*""\s*,\s*""([^""]+)""",
        RegexOptions.Compiled | RegexOptions.Multiline);

    /// <summary>C# projects listed in the solution, as existing absolute paths. Empty when none can be read.</summary>
    public static IReadOnlyList<FileInfo> ReadProjects(FileInfo solutionFile)
    {
        var relativePaths = solutionFile.Extension.Equals(".slnx", StringComparison.OrdinalIgnoreCase)
            ? ReadSlnxPaths(solutionFile)
            : ReadSlnPaths(solutionFile);

        var solutionDir = solutionFile.DirectoryName!;
        var projects = new List<FileInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var relative in relativePaths)
        {
            if (!relative.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
                continue;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(
                    Path.Combine(solutionDir, relative.Replace('\\', Path.DirectorySeparatorChar)));
            }
            catch (ArgumentException)
            {
                continue;
            }

            if (File.Exists(fullPath) && seen.Add(fullPath))
                projects.Add(new FileInfo(fullPath));
        }

        return projects;
    }

    private static IEnumerable<string> ReadSlnPaths(FileInfo solutionFile)
    {
        string content;
        try { content = File.ReadAllText(solutionFile.FullName); }
        catch (IOException) { return []; }

        return SlnProjectLine.Matches(content).Select(m => m.Groups[1].Value);
    }

    private static IEnumerable<string> ReadSlnxPaths(FileInfo solutionFile)
    {
        XDocument xml;
        try { xml = XDocument.Load(solutionFile.FullName); }
        catch { return []; }

        return xml.Descendants()
            .Where(e => e.Name.LocalName == "Project")
            .Select(e => (string?)e.Attribute("Path"))
            .Where(path => !string.IsNullOrEmpty(path))
            .Select(path => path!);
    }
}
