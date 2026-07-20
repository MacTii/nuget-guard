using NuGetGuard.Models;

namespace NuGetGuard.Services;

/// <summary>
/// Finds direct package references whose namespaces never appear in the project's source.
///
/// Entirely local — reads the restored assemblies and the source files, no network calls.
/// The result is a list of *candidates*: packages wired up through configuration, dependency
/// injection or reflection legitimately show up here, so findings need review before removal.
/// </summary>
public sealed class UnusedPackageAnalyzer
{
    /// <summary>Packages that never appear in source by design — build-time, test or tooling infrastructure.</summary>
    private static readonly HashSet<string> ToolingPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.NET.Test.Sdk", "Microsoft.TestPlatform.TestHost", "Microsoft.CodeCoverage",
        "coverlet.collector", "coverlet.msbuild", "xunit.runner.visualstudio", "xunit.runner.console",
        "NUnit3TestAdapter", "MSTest.TestAdapter", "Fody", "grpc.tools",
        "Microsoft.CodeDom.Providers.DotNetCompilerPlatform", "Microsoft.Web.Infrastructure",
        "Microsoft.EntityFrameworkCore.Tools", "Microsoft.VisualStudio.Web.CodeGeneration.Design",
        "Microsoft.NETCore.Platforms", "NETStandard.Library", "Microsoft.AspNet.Web.Optimization",
    };

    private static readonly string[] ToolingSuffixes =
        [".Design", ".Tools", ".Analyzers", ".Fody", ".SourceGenerator", ".SourceGenerators", ".Build.Tasks", ".MSBuild"];

    private static readonly string[] ToolingPrefixes =
        ["runtime.", "Microsoft.SourceLink.", "Microsoft.Net.Compilers", "StyleCop.", "SonarAnalyzer.", "Roslynator."];

    private readonly Dictionary<string, IReadOnlyCollection<string>> _namespaceCache =
        new(StringComparer.OrdinalIgnoreCase);

    public List<UnusedProjectGroup> Analyze(
        SolutionContext context,
        Action<string>? onProgress = null,
        CancellationToken ct = default)
    {
        var groups = new List<UnusedProjectGroup>();
        var centralVersions = ProjectFileReader.ReadCentralPackageVersions(context.SolutionFile.DirectoryName!);

        foreach (var project in context.ProjectFiles)
        {
            ct.ThrowIfCancellationRequested();
            onProgress?.Invoke(Path.GetFileNameWithoutExtension(project.Name));

            var group = AnalyzeProject(project, centralVersions, context.PackagesFolder);
            if (group is not null)
                groups.Add(group);
        }

        return groups;
    }

    private UnusedProjectGroup? AnalyzeProject(
        FileInfo project,
        IReadOnlyDictionary<string, string> centralVersions,
        string? packagesFolder)
    {
        var direct = ProjectFileReader.ReadDirectPackages(project.FullName, centralVersions);
        if (direct.Count == 0)
            return null;

        var usedNamespaces = SourceNamespaceScanner.ScanFiles(CollectSourceFiles(project));

        // No readable source means no evidence either way — reporting everything would be noise.
        if (usedNamespaces.Count == 0)
            return null;

        var isLegacy = ProjectFileReader.IsLegacyProject(project);

        // packages.config lists the full dependency closure, so anything another listed package
        // pulls in is not a real direct reference and must not be judged on its own.
        var pulledInByOthers = isLegacy
            ? CollectTransitiveIds(direct, packagesFolder)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var group = new UnusedProjectGroup
        {
            ProjectName = Path.GetFileNameWithoutExtension(project.Name),
            IsLegacy = isLegacy,
        };

        foreach (var (id, version) in direct)
        {
            if (IsExcluded(id) || pulledInByOthers.Contains(id))
                continue;

            var namespaces = GetPackageNamespaces(id, version, packagesFolder);

            // No assemblies (content-only, analyzers, targets) or package not restored — nothing to judge.
            if (namespaces.Count == 0)
                continue;

            if (namespaces.Any(usedNamespaces.Contains))
                continue;

            group.Items.Add(new UnusedPackage(id, version, DescribeNamespaces(namespaces)));
        }

        if (group.Items.Count == 0)
            return null;

        group.Items.Sort((a, b) => string.Compare(a.Package, b.Package, StringComparison.OrdinalIgnoreCase));
        return group;
    }

    private static IEnumerable<string> CollectSourceFiles(FileInfo project)
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in SourceNamespaceScanner.EnumerateSourceFiles(project.DirectoryName!))
            files.Add(path);

        // Linked files live outside the project folder but still compile into it
        foreach (var path in ProjectFileReader.GetIncludedFilePaths(project.FullName))
            files.Add(path);

        return files;
    }

    /// <summary>Ids that appear as a dependency of another package listed in the same project.</summary>
    private static HashSet<string> CollectTransitiveIds(
        IReadOnlyDictionary<string, string> packages, string? packagesFolder)
    {
        var transitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (packagesFolder is null)
            return transitive;

        foreach (var (id, version) in packages)
        {
            var packageDir = Path.Combine(packagesFolder, $"{id}.{version}");
            if (!Directory.Exists(packageDir))
                continue;

            var nuspec = Directory.EnumerateFiles(packageDir, "*.nuspec", SearchOption.AllDirectories).FirstOrDefault();
            if (nuspec is null)
                continue;

            foreach (var dependency in NuspecDependencyReader.ReadDependencyIds(nuspec))
                transitive.Add(dependency);
        }

        return transitive;
    }

    private IReadOnlyCollection<string> GetPackageNamespaces(string id, string version, string? packagesFolder)
    {
        var key = $"{id}|{version}";
        if (_namespaceCache.TryGetValue(key, out var cached))
            return cached;

        var namespaces = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var assembly in PackageAssemblyLocator.FindAssemblies(id, version, packagesFolder))
        {
            foreach (var ns in AssemblyNamespaceReader.ReadPublicNamespaces(assembly))
                namespaces.Add(ns);
        }

        _namespaceCache[key] = namespaces;
        return namespaces;
    }

    private static string DescribeNamespaces(IReadOnlyCollection<string> namespaces)
    {
        var shown = namespaces.OrderBy(ns => ns, StringComparer.OrdinalIgnoreCase).Take(3).ToList();
        var suffix = namespaces.Count > shown.Count ? $", +{namespaces.Count - shown.Count} more" : string.Empty;
        return string.Join(", ", shown) + suffix;
    }

    private static bool IsExcluded(string id) =>
        FrameworkPolyfills.Contains(id)
        || ToolingPackages.Contains(id)
        || ToolingSuffixes.Any(suffix => id.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        || ToolingPrefixes.Any(prefix => id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
}
