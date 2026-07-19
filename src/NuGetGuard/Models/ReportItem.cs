namespace NuGetGuard.Models;

/// <summary>A single row in the Vulnerable / Deprecated / Outdated report.</summary>
public sealed class ReportItem
{
    public required string Category { get; init; }
    public required string Package { get; init; }
    public required string Version { get; init; }
    public string? Severity { get; init; }
    public string? Advisory { get; init; }
    public string? Message { get; init; }
    public string? Alternative { get; init; }
    public List<string> Projects { get; } = [];

    public string ProjectsDisplay => string.Join(", ", Projects);

    public void AddProjects(IEnumerable<string> names)
    {
        foreach (var name in names)
        {
            if (!string.IsNullOrEmpty(name) && !Projects.Contains(name, StringComparer.OrdinalIgnoreCase))
                Projects.Add(name);
        }
    }
}
