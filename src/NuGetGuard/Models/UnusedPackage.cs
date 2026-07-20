namespace NuGetGuard.Models;

/// <summary>
/// A direct package reference whose namespaces were not found anywhere in the project's source.
/// Heuristic — packages used only via configuration, DI or reflection can appear here.
/// </summary>
public sealed record UnusedPackage(string Package, string Version, string Namespaces);
