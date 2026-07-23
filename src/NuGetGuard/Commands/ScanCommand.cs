using NuGetGuard.Models;
using NuGetGuard.Reporting;
using NuGetGuard.Services;
using NuGetGuard.Services.ClearlyDefined;
using NuGetGuard.Services.NuGetApi;
using Spectre.Console;
using Spectre.Console.Cli;

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
                $"[yellow]⚠️  {others} more {(others == 1 ? "solution" : "solutions")} found here and not scanned — point the path at one to scan it.[/]");
        }

        AnsiConsole.WriteLine();

        var allPackages = PackageCollector.CollectPackages(solution);
        await RestoreLegacyProjectsAsync(solution);

        var http = SharedHttpClient.Instance;
        var nuget = new NuGetClient(http);
        var builder = new ReportBuilder(nuget);

        var metadata = await FetchMetadataWithProgressAsync(builder, allPackages.Values.ToList());
        await ResolveLicensesWithProgressAsync(metadata, http, solution.PackagesFolder, settings.OnlineLicenses);

        var (vulnerable, skippedProjects) = await ReportBuilder.BuildVulnerableAsync(
            solution, metadata,
            onInfo: message => AnsiConsole.MarkupLine($"[grey]ℹ️  {Markup.Escape(message)}[/]"));
        var (outdated, outdatedFailed) = await builder.BuildOutdatedAsync(solution);
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
            Deprecated = ReportBuilder.BuildDeprecated(metadata),
            Outdated = outdated,
            OutdatedScanFailed = outdatedFailed,
            Licenses = ReportBuilder.BuildLicenses(metadata),
            Redundant = redundant,
            Unused = unused,
            SkippedProjects = skippedProjects,
        };

        ConsoleReporter.Render(report);
        ReportExporter.Export(report, settings.Export, settings.OutputFile, openHtml: !settings.NoOpen);

        return ExitCodeResolver.Resolve(report, settings.FailOn);
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
        ReportBuilder builder, IReadOnlyCollection<CollectedPackage> packages)
    {
        List<PackageMetadata> metadata = [];

        await AnsiConsole.Progress()
            .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new SpinnerColumn())
            .StartAsync(async progress =>
            {
                var task = progress.AddTask("[cyan]Fetching NuGet metadata[/]", maxValue: packages.Count);
                metadata = await builder.FetchMetadataAsync(packages, onPackageDone: () => task.Increment(1));
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
        var resolved = await ReportBuilder.ResolveRemainingLicensesAsync(
            metadata, new LicenseUrlResolver(http), legacyPackagesFolder, clearlyDefined);

        AnsiConsole.MarkupLine(
            $"[green]✅ Identified {resolved} more, {unresolvedCount - resolved} left unknown[/]\n");
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
