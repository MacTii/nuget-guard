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
    /// <summary>The file, picked up automatically when it sits next to the solution.</summary>
    public const string FileName = "nuget-guard.licenses.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Package id → licence, read from the file beside the solution. Returns empty when it is
    /// absent or unreadable: a broken override file must not abort a scan, and the packages
    /// simply stay as they were.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Load(string solutionDirectory)
    {
        var empty = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(solutionDirectory, FileName);
        if (!File.Exists(path))
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
