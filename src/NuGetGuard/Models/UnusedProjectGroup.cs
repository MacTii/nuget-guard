namespace NuGetGuard.Models;

public sealed class UnusedProjectGroup
{
    public required string ProjectName { get; init; }
    public required bool IsLegacy { get; init; }
    public List<UnusedPackage> Items { get; } = [];
}
