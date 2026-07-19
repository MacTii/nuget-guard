namespace NuGetGuard.Models;

public sealed class RedundantProjectGroup
{
    public required string ProjectName { get; init; }
    public required bool IsLegacy { get; init; }
    public required bool IsSdkStyle { get; init; }
    public List<RedundantPackage> Items { get; } = [];
}
