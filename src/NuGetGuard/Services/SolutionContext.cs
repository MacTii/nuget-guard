namespace NuGetGuard.Services;

/// <summary>The discovered solution file and its projects.</summary>
public sealed record SolutionContext(FileInfo SolutionFile, IReadOnlyList<FileInfo> ProjectFiles)
{
    public string? PackagesFolder
    {
        get
        {
            var path = Path.Combine(SolutionFile.DirectoryName!, "packages");
            return Directory.Exists(path) ? path : null;
        }
    }
}
