using NuGet.Versioning;
using NuGetGuard.Models;
using NuGetGuard.Services.Discovery;
using NuGetGuard.Services.NuGetApi;
using NuGetGuard.Services.Packages;

namespace NuGetGuard.Services.Analysis;

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

        // Transitive closure of every direct package: covered id → the highest dependency floor
        // reached for it, i.e. the version that would resolve if the direct reference were removed.
        var closures = new Dictionary<string, Dictionary<string, NuGetVersion?>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, version) in direct)
        {
            var visited = new Dictionary<string, NuGetVersion?>(StringComparer.OrdinalIgnoreCase);
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
                if (!closures[other].TryGetValue(candidate, out var coveredFloor))
                    continue;

                var note = VersionNote(candidateVersion, coveredFloor);
                if (projectRefPackages.ContainsKey(other))
                    note = Join($"also in ProjectRef → {projectRefPackages[other].Source}", note);

                group.Items.Add(new RedundantPackage(candidate, candidateVersion, other, otherVersion, note));
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

                // Same version → the explicit reference is a safe no-op to remove. A different
                // version means removing it changes what resolves, so flag that rather than
                // presenting it as a harmless duplicate.
                var label = $"ProjectRef → {source.Source}";
                var note = string.Equals(source.Version, candidateVersion, StringComparison.OrdinalIgnoreCase)
                    ? ""
                    : "⚠ version differs — removing changes it";
                group.Items.Add(new RedundantPackage(candidate, candidateVersion, label, source.Version, note));
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
        Dictionary<string, NuGetVersion?> visited,
        CancellationToken ct)
    {
        var dependencies = await GetDependenciesAsync(id, version, packagesFolder, ct);

        foreach (var dep in dependencies)
        {
            var floor = ParseFloor(dep.VersionRange);

            if (visited.TryGetValue(dep.Id, out var existing))
            {
                // Reached again via another path — NuGet resolves to the highest floor, so keep it.
                if (floor is not null && (existing is null || floor > existing))
                    visited[dep.Id] = floor;
                continue;
            }

            visited[dep.Id] = floor;
            if (versionLookup.TryGetValue(dep.Id, out var depVersion))
                await WalkClosureAsync(dep.Id, depVersion, packagesFolder, versionLookup, visited, ct);
        }
    }

    private async Task<IReadOnlyList<DependencyRef>> GetDependenciesAsync(
        string id, string version, string? packagesFolder, CancellationToken ct)
    {
        // 1. Local nuspec from packages folder (legacy projects) — no HTTP
        var local = NuspecDependencyReader.ReadDependencies(packagesFolder, id, version);
        if (local.Count > 0)
            return local;

        // 2. NuGet registration API fallback (cached inside NuGetClient)
        return await nuget.GetDependenciesAsync(id, version, ct);
    }

    private static NuGetVersion? ParseFloor(string? range) =>
        !string.IsNullOrWhiteSpace(range) && VersionRange.TryParse(range, out var parsed)
            ? parsed.MinVersion
            : null;

    /// <summary>
    /// The version relationship between a pinned reference and the floor its covering chain imposes.
    /// Blank when they match (a safe no-op removal) or cannot be compared.
    /// </summary>
    private static string VersionNote(string pinnedVersion, NuGetVersion? coveredFloor)
    {
        if (coveredFloor is null || !NuGetVersion.TryParse(pinnedVersion, out var pinned) || pinned == coveredFloor)
            return "";

        return $"⚠ version differs — transitive brings {coveredFloor}";
    }

    private static string Join(string a, string b) =>
        string.IsNullOrEmpty(b) ? a : string.IsNullOrEmpty(a) ? b : $"{a}; {b}";
}
