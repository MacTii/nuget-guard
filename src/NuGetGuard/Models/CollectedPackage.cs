namespace NuGetGuard.Models;

/// <summary>A package reference collected from project files, with the projects that use it.</summary>
public sealed class CollectedPackage
{
    public required string Id { get; init; }
    public required string Version { get; init; }
    public HashSet<string> Projects { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string Key => $"{Id}|{Version}";
}
