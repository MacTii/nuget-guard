namespace NuGetGuard.Services;

/// <summary>Finds the solution file and the projects belonging to it.</summary>
public static class SolutionDiscovery
{
    private static readonly string[] ExcludedDirs =
    [
        $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}",
    ];

    public static SolutionContext? Discover(string rootPath)
    {
        var solutions = FindSolutions(rootPath);
        if (solutions.Count == 0)
            return null;

        var solution = solutions[0];

        // The solution file is the source of truth; a folder may hold several unrelated solutions.
        var projects = SolutionProjectReader.ReadProjects(solution);

        // Malformed or empty solution — fall back to the solution's own folder, never the scan root.
        if (projects.Count == 0)
            projects = EnumerateProjects(solution.DirectoryName!);

        return new SolutionContext(solution, projects)
        {
            OtherSolutions = solutions.Skip(1).ToList(),
        };
    }

    /// <summary>All solutions under the path, shortest path first.</summary>
    public static IReadOnlyList<FileInfo> FindSolutions(string rootPath)
    {
        var root = new DirectoryInfo(rootPath);
        if (!root.Exists)
            return [];

        return root.EnumerateFiles("*.sln", SearchOption.AllDirectories)
            .Concat(root.EnumerateFiles("*.slnx", SearchOption.AllDirectories))
            .Where(NotInExcludedDir)
            .OrderBy(f => f.FullName.Length)
            .ToList();
    }

    private static List<FileInfo> EnumerateProjects(string directory) =>
        new DirectoryInfo(directory)
            .EnumerateFiles("*.csproj", SearchOption.AllDirectories)
            .Where(NotInExcludedDir)
            .OrderBy(f => f.FullName, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static bool NotInExcludedDir(FileInfo file) =>
        !ExcludedDirs.Any(d => file.FullName.Contains(d, StringComparison.OrdinalIgnoreCase));
}
