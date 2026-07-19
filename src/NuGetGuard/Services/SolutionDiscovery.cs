namespace NuGetGuard.Services;

/// <summary>Finds the solution file and its projects under a root directory.</summary>
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
        var root = new DirectoryInfo(rootPath);
        if (!root.Exists)
            return null;

        var solution = root.EnumerateFiles("*.sln", SearchOption.AllDirectories)
            .Concat(root.EnumerateFiles("*.slnx", SearchOption.AllDirectories))
            .Where(NotInExcludedDir)
            .OrderBy(f => f.FullName.Length)
            .FirstOrDefault();

        if (solution is null)
            return null;

        var projects = root.EnumerateFiles("*.csproj", SearchOption.AllDirectories)
            .Where(NotInExcludedDir)
            .OrderBy(f => f.FullName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new SolutionContext(solution, projects);
    }

    private static bool NotInExcludedDir(FileInfo file) =>
        !ExcludedDirs.Any(d => file.FullName.Contains(d, StringComparison.OrdinalIgnoreCase));
}
