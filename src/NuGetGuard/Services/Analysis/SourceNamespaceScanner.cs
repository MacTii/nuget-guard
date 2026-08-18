using System.Text.RegularExpressions;

namespace NuGetGuard.Services.Analysis;

/// <summary>
/// Collects every namespace-shaped token that appears in a project's source files.
///
/// Text-based on purpose: it needs no successful build and works on legacy project formats.
/// Comments and string literals are deliberately *not* stripped — a namespace mentioned in a
/// comment counts as "used", which biases the analysis towards under-reporting. Claiming a
/// used package is unused is harmful; missing one is not.
/// </summary>
public static class SourceNamespaceScanner
{
    private static readonly string[] SourceExtensions =
        [".cs", ".cshtml", ".razor", ".vb", ".vbhtml", ".aspx", ".ascx", ".ashx", ".fs"];

    private static readonly string[] ExcludedDirs =
    [
        $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
        $"{Path.DirectorySeparatorChar}node_modules{Path.DirectorySeparatorChar}",
    ];

    // `using X.Y;`, `global using static X.Y;`, `using Alias = X.Y;`, `@using X.Y`, `Imports X.Y`
    private static readonly Regex ImportDirective = new(
        @"(?:^|\s)@?(?:global\s+)?(?:using|Imports)\s+(?:static\s+)?(?:[A-Za-z_]\w*\s*=\s*)?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    // Any dotted chain — catches fully qualified usage such as Newtonsoft.Json.JsonConvert.SerializeObject
    private static readonly Regex DottedIdentifier = new(
        @"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+",
        RegexOptions.Compiled);

    private const long MaxFileSizeBytes = 4 * 1024 * 1024;

    /// <summary>Namespace tokens (and all their prefixes) referenced by the given source files.</summary>
    public static HashSet<string> ScanFiles(IEnumerable<string> filePaths)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in filePaths)
        {
            string content;
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists || info.Length > MaxFileSizeBytes)
                    continue;
                content = File.ReadAllText(path);
            }
            catch (IOException)
            {
                continue;
            }

            foreach (Match match in ImportDirective.Matches(content))
                AddWithPrefixes(used, match.Groups[1].Value);

            foreach (Match match in DottedIdentifier.Matches(content))
                AddWithPrefixes(used, match.Value);
        }

        return used;
    }

    /// <summary>Adds namespaces that are not written in the source, such as MSBuild global usings.</summary>
    public static void AddNamespaces(HashSet<string> used, IEnumerable<string> namespaces)
    {
        foreach (var ns in namespaces)
            AddWithPrefixes(used, ns);
    }

    /// <summary>Source files belonging to a project: everything under its folder, minus build output.</summary>
    public static IEnumerable<string> EnumerateSourceFiles(string projectDirectory)
    {
        if (!Directory.Exists(projectDirectory))
            return [];

        return Directory
            .EnumerateFiles(projectDirectory, "*.*", SearchOption.AllDirectories)
            .Where(IsSourceFile)
            .Where(path => !ExcludedDirs.Any(dir => path.Contains(dir, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool IsSourceFile(string path) =>
        SourceExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds "A.B.C" plus "A.B" and "A" so that both imports and qualified usage match.</summary>
    private static void AddWithPrefixes(HashSet<string> used, string value)
    {
        if (string.IsNullOrEmpty(value))
            return;

        var index = 0;
        while (true)
        {
            var next = value.IndexOf('.', index);
            if (next < 0)
                break;
            used.Add(value[..next]);
            index = next + 1;
        }
        used.Add(value);
    }
}
