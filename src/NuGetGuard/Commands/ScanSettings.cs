using System.ComponentModel;
using NuGetGuard.Reporting;
using Spectre.Console.Cli;

namespace NuGetGuard.Commands;

public sealed class ScanSettings : CommandSettings
{
    [CommandArgument(0, "[path]")]
    [Description("Path to the folder containing the solution. Defaults to the current directory.")]
    public string Path { get; init; } = ".";

    [CommandOption("-e|--export")]
    [Description("Export format: None, Csv or Html.")]
    public ExportFormat Export { get; init; } = ExportFormat.None;

    [CommandOption("-o|--output")]
    [Description("Output file name without extension. Defaults to 'nuget-report'.")]
    public string OutputFile { get; init; } = "nuget-report";

    [CommandOption("--fail-on")]
    [Description("Return a non-zero exit code when issues of the given kind are found: None, Vulnerable, Deprecated, Outdated, StrongCopyleft or Any. Useful in CI.")]
    public FailOn FailOn { get; init; } = FailOn.None;

    [CommandOption("--skip-redundant")]
    [Description("Skip the redundant-packages (transitive coverage) analysis.")]
    public bool SkipRedundant { get; init; }

    [CommandOption("--no-open")]
    [Description("Do not open the HTML report in the browser after export.")]
    public bool NoOpen { get; init; }
}
