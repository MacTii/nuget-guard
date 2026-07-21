using System.Xml.Linq;

namespace NuGetGuard.Services;

/// <summary>
/// Reads the licence file a package ships and identifies it.
///
/// Modern packages declare <c>&lt;license type="file"&gt;</c> instead of a licence URL, and the
/// nuget.org page for those renders the text through scripting, so downloading it yields nothing.
/// The restored package holds the file itself, which makes this both offline and reliable.
/// </summary>
public static class PackageLicenseFileReader
{
    private static readonly string[] ConventionalNames =
        ["LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt", "COPYING", "license.txt"];

    private const long MaxFileSizeBytes = 1024 * 1024;

    /// <summary>The SPDX id of the licence shipped with the package, or null when there is none to read.</summary>
    public static string? Read(string id, string version, string? legacyPackagesFolder)
    {
        var packageFolder = PackageFolderLocator.Find(id, version, legacyPackagesFolder);
        if (packageFolder is null)
            return null;

        var licensePath = FindDeclaredFile(packageFolder) ?? FindConventionalFile(packageFolder);
        if (licensePath is null)
            return null;

        try
        {
            var file = new FileInfo(licensePath);
            if (!file.Exists || file.Length > MaxFileSizeBytes)
                return null;

            return SpdxTextMatcher.Identify(File.ReadAllText(licensePath));
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>The file named by the .nuspec, which is authoritative when present.</summary>
    private static string? FindDeclaredFile(string packageFolder)
    {
        string nuspecPath;
        try
        {
            nuspecPath = Directory.EnumerateFiles(packageFolder, "*.nuspec").FirstOrDefault() ?? "";
        }
        catch (IOException)
        {
            return null;
        }

        if (nuspecPath.Length == 0)
            return null;

        XDocument nuspec;
        try { nuspec = XDocument.Load(nuspecPath); }
        catch { return null; }

        var license = nuspec.Descendants().FirstOrDefault(e => e.Name.LocalName == "license");
        if (license is null || (string?)license.Attribute("type") != "file")
            return null;

        var relative = license.Value.Trim();
        if (relative.Length == 0)
            return null;

        var path = Path.Combine(packageFolder, relative.Replace('/', Path.DirectorySeparatorChar));
        return File.Exists(path) ? path : null;
    }

    private static string? FindConventionalFile(string packageFolder)
    {
        foreach (var name in ConventionalNames)
        {
            var path = Path.Combine(packageFolder, name);
            if (File.Exists(path))
                return path;
        }
        return null;
    }
}
