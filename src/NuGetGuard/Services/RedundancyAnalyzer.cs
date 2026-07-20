using NuGetGuard.Models;
using NuGetGuard.Services.NuGetApi;

namespace NuGetGuard.Services;

/// <summary>
/// Snitch-like analysis: finds direct package references that are already covered
/// transitively by another direct reference or by a referenced project.
/// </summary>
public sealed class RedundancyAnalyzer(NuGetClient nuget)
{
    public async Task<List<RedundantProjectGroup>> AnalyzeAsync(
        SolutionContext context,
        Dictionary<string, CollectedPackage> allPackages,
        Action<string>? onProgress = null,
        CancellationToken ct = default)
    {
        var groups = new List<RedundantProjectGroup>();
        var packagesFolder = context.PackagesFolder;

        // Id → version lookup used to walk the transitive closure with concrete versions
        var versionLookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in allPackages.Values)
            versionLookup.TryAdd(package.Id, package.Version);

        foreach (var project in context.ProjectFiles)
        {
            ct.ThrowIfCancellationRequested();
            onProgress?.Invoke(Path.GetFileNameWithoutExtension(project.Name));

            var group = await AnalyzeProjectAsync(project, packagesFolder, versionLookup, ct);
            if (group is not null)
                groups.Add(group);
        }

        return groups;
    }

    private async Task<RedundantProjectGroup?> AnalyzeProjectAsync(
        FileInfo project,
        string? packagesFolder,
        IReadOnlyDictionary<string, string> versionLookup,
        CancellationToken ct)
    {
        var isLegacy = ProjectFileReader.IsLegacyProject(project);
        var isSdkStyle = ProjectFileReader.IsSdkStyleProject(project);
        var direct = ProjectFileReader.ReadDirectPackages(project.FullName);

        if (direct.Count < 2)
            return null;

        // Direct packages of all referenced projects (recursively)
        var projectRefPackages = new Dictionary<string, (string Version, string Source)>(StringComparer.OrdinalIgnoreCase);
        foreach (var refPath in ProjectFileReader.GetProjectReferenceClosure(project.FullName))
        {
            var refName = Path.GetFileNameWithoutExtension(refPath);
            foreach (var (id, version) in ProjectFileReader.ReadDirectPackages(refPath))
                projectRefPackages.TryAdd(id, (version, refName));
        }

        // Transitive closure of every direct package
        var closures = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, version) in direct)
        {
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            await WalkClosureAsync(id, version, packagesFolder, versionLookup, visited, ct);
            closures[id] = visited;
        }

        var group = new RedundantProjectGroup
        {
            ProjectName = Path.GetFileNameWithoutExtension(project.Name),
            IsLegacy = isLegacy,
            IsSdkStyle = isSdkStyle,
        };

        foreach (var (candidate, candidateVersion) in direct)
        {
            if (!isSdkStyle && FrameworkPolyfills.Contains(candidate))
                continue;

            foreach (var (other, otherVersion) in direct)
            {
                if (string.Equals(candidate, other, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!closures[other].Contains(candidate))
                    continue;

                var sourceNote = projectRefPackages.ContainsKey(other)
                    ? $"also in ProjectRef → {projectRefPackages[other].Source}"
                    : "this project";

                group.Items.Add(new RedundantPackage(candidate, candidateVersion, other, otherVersion, sourceNote));
                break;
            }
        }

        // SDK-style: also flag packages already provided by a referenced project
        if (isSdkStyle && projectRefPackages.Count > 0)
        {
            foreach (var (candidate, candidateVersion) in direct)
            {
                if (FrameworkPolyfills.Contains(candidate))
                    continue;
                if (group.Items.Any(i => string.Equals(i.Package, candidate, StringComparison.OrdinalIgnoreCase)))
                    continue;
                if (!projectRefPackages.TryGetValue(candidate, out var source))
                    continue;

                var label = $"ProjectRef → {source.Source}";
                group.Items.Add(new RedundantPackage(candidate, candidateVersion, label, source.Version, label));
            }
        }

        if (group.Items.Count == 0)
            return null;

        group.Items.Sort((a, b) => string.Compare(a.Package, b.Package, StringComparison.OrdinalIgnoreCase));
        return group;
    }

    private async Task WalkClosureAsync(
        string id,
        string version,
        string? packagesFolder,
        IReadOnlyDictionary<string, string> versionLookup,
        HashSet<string> visited,
        CancellationToken ct)
    {
        var dependencies = await GetDependencyIdsAsync(id, version, packagesFolder, ct);

        foreach (var depId in dependencies)
        {
            if (!visited.Add(depId))
                continue;
            if (versionLookup.TryGetValue(depId, out var depVersion))
                await WalkClosureAsync(depId, depVersion, packagesFolder, versionLookup, visited, ct);
        }
    }

    private async Task<IReadOnlyList<string>> GetDependencyIdsAsync(
        string id, string version, string? packagesFolder, CancellationToken ct)
    {
        // 1. Local nuspec from packages folder (legacy projects) — no HTTP
        if (packagesFolder is not null)
        {
            var packageDir = Path.Combine(packagesFolder, $"{id}.{version}");
            if (Directory.Exists(packageDir))
            {
                var nuspec = Directory.EnumerateFiles(packageDir, "*.nuspec", SearchOption.AllDirectories).FirstOrDefault();
                if (nuspec is not null)
                {
                    var deps = NuspecDependencyReader.ReadDependencyIds(nuspec);
                    if (deps.Count > 0)
                        return deps;
                }
            }
        }

        // 2. NuGet registration API fallback (cached inside NuGetClient)
        return await nuget.GetDependencyIdsAsync(id, version, ct);
    }
}
