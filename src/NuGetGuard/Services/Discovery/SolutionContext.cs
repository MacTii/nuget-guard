namespace NuGetGuard.Services.Discovery;

/// <summary>The discovered solution file and its projects.</summary>
public sealed record SolutionContext(FileInfo SolutionFile, IReadOnlyList<FileInfo> ProjectFiles)
{
    /// <summary>Other solutions found under the scanned path — none of them was scanned.</summary>
    public IReadOnlyList<FileInfo> OtherSolutions { get; init; } = [];

    public string? PackagesFolder
    {
        get
        {
            var path = Path.Combine(SolutionFile.DirectoryName!, "packages");
            return Directory.Exists(path) ? path : null;
        }
    }
}
