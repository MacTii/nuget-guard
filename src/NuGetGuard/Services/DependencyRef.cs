namespace NuGetGuard.Services;

/// <summary>A declared package dependency — its id and version range (null when the .nuspec omits it).</summary>
public sealed record DependencyRef(string Id, string? VersionRange);
