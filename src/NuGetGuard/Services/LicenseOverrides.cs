using System.Text.Json;
using NuGetGuard.Models;

namespace NuGetGuard.Services;

/// <summary>
/// Licences declared by the team scanning, read from a JSON file of package id → licence.
///
/// No public database can cover packages from a private feed, so this is the only way those stop
/// reporting as unknown. Overrides win over every other source, including the package's own
/// metadata: an organisation stating what it uses is more authoritative than a mislabelled feed.
/// </summary>
public static class LicenseOverrides
{
    /// <summary>File picked up automatically when it sits next to the solution.</summary>
    public const string ConventionalFileName = "nuget-guard.licenses.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>The override file to use: the explicit one, else the conventional one beside the solution.</summary>
    public static string? Locate(string? explicitPath, string solutionDirectory)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return explicitPath;

        var conventional = Path.Combine(solutionDirectory, ConventionalFileName);
        return File.Exists(conventional) ? conventional : null;
    }

    /// <summary>
    /// Package id → licence. Returns empty when the file is missing or unreadable; a broken
    /// override file must not abort a scan, and the packages simply stay as they were.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Load(string? path)
    {
        var empty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return empty;

        try
        {
            var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path), JsonOptions);
            if (parsed is null)
                return empty;

            return new Dictionary<string, string>(parsed, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is JsonException or IOException)
        {
            return empty;
        }
    }

    /// <summary>Applies the overrides and returns how many packages they covered.</summary>
    public static int Apply(IEnumerable<PackageMetadata> metadata, IReadOnlyDictionary<string, string> overrides)
    {
        if (overrides.Count == 0)
            return 0;

        var applied = 0;
        foreach (var package in metadata)
        {
            if (!overrides.TryGetValue(package.Id, out var license) || string.IsNullOrWhiteSpace(license))
                continue;

            package.License = license.Trim();
            applied++;
        }

        return applied;
    }
}
