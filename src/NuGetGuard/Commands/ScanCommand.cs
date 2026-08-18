using NuGetGuard.Models;
using NuGetGuard.Reporting;
using NuGetGuard.Services.Analysis;
using NuGetGuard.Services.Discovery;
using NuGetGuard.Services.Licensing.ClearlyDefined;
using NuGetGuard.Services.Licensing;
using NuGetGuard.Services.NuGetApi;
using NuGetGuard.Services.Packages;
using NuGetGuard.Services.Reports;
using NuGetGuard.Services;
using Spectre.Console.Cli;
using Spectre.Console;

namespace NuGetGuard.Commands;

/// <summary>
/// Presentation layer: wires the scan pipeline together, renders progress
/// and the final report, delegates export and exit-code resolution.
/// </summary>
public sealed class ScanCommand : AsyncCommand<ScanSettings>
{
    protected override async Task<int> ExecuteAsync(
        CommandContext context, ScanSettings settings, CancellationToken cancellationToken)
    {
        var root = System.IO.Path.GetFullPath(settings.Path);

        var solution = SolutionDiscovery.Discover(root);
        if (solution is null)
        {
            AnsiConsole.MarkupLine($"[red]❌ No .sln/.slnx file found under {Markup.Escape(root)}[/]");
            return ExitCodeResolver.NoSolutionFound;
        }

        var projectCount = solution.ProjectFiles.Count;
        AnsiConsole.MarkupLine(
            $"\n[cyan]🔍 Scanning solution: {Markup.Escape(solution.SolutionFile.Name)}[/] [grey]({projectCount} {(projectCount == 1 ? "project" : "projects")})[/]");

        var others = solution.OtherSolutions.Count;
        if (others > 0)
        {
            AnsiConsole.MarkupLine(
                $"[yellow]⚠️  {others} more {(others == 1 ? "solution" : "solutions")} found here and not scanned — pass one of these paths to scan it:[/]");

            var cwd = Directory.GetCurrentDirectory();
            foreach (var other in solution.OtherSolutions)
                AnsiConsole.MarkupLine($"[grey]     {Markup.Escape(RelativeOrFull(cwd, other.FullName))}[/]");
        }

        AnsiConsole.WriteLine();

        var allPackages = PackageCollector.CollectPackages(solution);
        await RestoreLegacyProjectsAsync(solution);

        var http = SharedHttpClient.Instance;
        var nuget = new NuGetClient(http);
        var fetcher = new PackageMetadataFetcher(nuget);

        var metadata = await FetchMetadataWithProgressAsync(fetcher, allPackages.Values.ToList());
        await ResolveLicensesWithProgressAsync(metadata, http, solution.PackagesFolder, settings.OnlineLicenses);

        var (vulnerable, skippedProjects) = await VulnerabilityReport.BuildAsync(
            solution, metadata,
            onInfo: message => AnsiConsole.MarkupLine($"[grey]ℹ️  {Markup.Escape(message)}[/]"));
        var (outdated, outdatedFailed) = await new OutdatedReport(nuget).BuildAsync(solution);
        var redundant = settings.SkipRedundant
            ? []
            : await AnalyzeRedundantWithProgressAsync(nuget, solution, allPackages);
        var unused = settings.SkipUnused
            ? []
            : AnalyzeUnusedWithProgress(solution);

        var report = new ScanReport
        {
            SolutionName = solution.SolutionFile.Name,
            Vulnerable = vulnerable,
            Deprecated = DeprecationReport.Build(metadata),
            Outdated = outdated,
            OutdatedScanFailed = outdatedFailed,
            Licenses = LicenseResolver.BuildItems(metadata),
            Redundant = redundant,
            RedundantSkipped = settings.SkipRedundant,
            Unused = unused,
            UnusedSkipped = settings.SkipUnused,
            SkippedProjects = skippedProjects,
        };

        ConsoleReporter.Render(report);
        ReportExporter.Export(report, settings.Export, settings.OutputFile, openHtml: !settings.NoOpen);

        return ExitCodeResolver.Resolve(report, settings.FailOn);
    }

    /// <summary>Path relative to the working directory when it is inside it, otherwise the full path.</summary>
    private static string RelativeOrFull(string root, string fullPath)
    {
        var relative = Path.GetRelativePath(root, fullPath);
        return relative.StartsWith("..", StringComparison.Ordinal) ? fullPath : relative;
    }

    private static async Task RestoreLegacyProjectsAsync(SolutionContext solution)
    {
        if (!LegacyRestorer.HasLegacyProjects(solution))
            return;

        AnsiConsole.MarkupLine("[cyan]🔄 Restoring legacy projects via nuget.exe...[/]");
        var outcome = await new LegacyRestorer(SharedHttpClient.Instance).RestoreAsync(solution);

        var message = outcome switch
        {
            LegacyRestoreOutcome.Restored =>
                "[green]✅ Legacy packages restored[/]\n",
            LegacyRestoreOutcome.NuGetExeUnavailable =>
                "[yellow]⚠️  Legacy projects detected but nuget.exe is unavailable — redundancy and unused analysis will be limited.[/]\n",
            LegacyRestoreOutcome.NoPackagesFolder =>
                "[yellow]⚠️  No packages/ folder produced by nuget restore — redundancy and unused analysis will be limited.[/]\n",
            _ => null,
        };
        if (message is not null)
            AnsiConsole.MarkupLine(message);
    }

    private static async Task<List<PackageMetadata>> FetchMetadataWithProgressAsync(
        PackageMetadataFetcher fetcher, IReadOnlyCollection<CollectedPackage> packages)
    {
        List<PackageMetadata> metadata = [];

        await AnsiConsole.Progress()
            .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new SpinnerColumn())
            .StartAsync(async progress =>
            {
                var task = progress.AddTask("[cyan]Fetching NuGet metadata[/]", maxValue: packages.Count);
                metadata = await fetcher.FetchAsync(packages, onPackageDone: () => task.Increment(1));
            });

        AnsiConsole.MarkupLine($"[green]✅ Metadata fetched for {packages.Count} packages[/]\n");
        return metadata;
    }

    private static async Task ResolveLicensesWithProgressAsync(
        List<PackageMetadata> metadata, HttpClient http, string? legacyPackagesFolder, bool online)
    {
        var unresolvedCount = metadata.Count(m => m.License == "Unknown");
        if (unresolvedCount == 0)
            return;

        var via = online ? ", ClearlyDefined included" : "";
        AnsiConsole.MarkupLine($"[cyan]🔄 Resolving {unresolvedCount} unidentified licenses{via}...[/]");

        var clearlyDefined = online ? new ClearlyDefinedClient(http) : null;
        var resolved = await LicenseResolver.ResolveRemainingAsync(
            metadata, new LicenseUrlResolver(http), legacyPackagesFolder, clearlyDefined);

        var stillUnknown = unresolvedCount - resolved;
        AnsiConsole.MarkupLine($"[green]✅ Identified {resolved} more, {stillUnknown} left unknown[/]");

        // Say what the next step is rather than leaving a bare number. "May" is
        // deliberate: most leftovers are packages with no published licence at all,
        // which no lookup can resolve.
        if (stillUnknown > 0 && !online)
            AnsiConsole.MarkupLine("[grey]   [/][cyan]--online-licenses[/][grey] may resolve some of these.[/]");

        AnsiConsole.WriteLine();
    }

    private static async Task<List<RedundantProjectGroup>> AnalyzeRedundantWithProgressAsync(
        NuGetClient nuget, SolutionContext solution, Dictionary<string, CollectedPackage> allPackages)
    {
        var analyzer = new RedundancyAnalyzer(nuget);
        List<RedundantProjectGroup> result = [];

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Analyzing transitive dependencies...", async statusContext =>
            {
                result = await analyzer.AnalyzeAsync(
                    solution, allPackages,
                    projectName => statusContext.Status($"Analyzing transitive deps: {Markup.Escape(projectName)}"));
            });

        return result;
    }

    private static List<UnusedProjectGroup> AnalyzeUnusedWithProgress(SolutionContext solution)
    {
        var analyzer = new UnusedPackageAnalyzer();
        List<UnusedProjectGroup> result = [];

        AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .Start("Scanning source for unused packages...", statusContext =>
            {
                result = analyzer.Analyze(
                    solution,
                    projectName => statusContext.Status($"Scanning source: {Markup.Escape(projectName)}"));
            });

        return result;
    }
}
