using System.ComponentModel;
using NuGetGuard.Reporting;
using Spectre.Console;
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

    [CommandOption("--skip-unused")]
    [Description("Skip the unused-packages analysis (scans source files for package namespaces).")]
    public bool SkipUnused { get; init; }

    [CommandOption("--online-licenses")]
    [Description("Query the ClearlyDefined API for licences the offline steps could not identify. Slower and needs network, but resolves packages not in the built-in database.")]
    public bool OnlineLicenses { get; init; }

    [CommandOption("--no-open")]
    [Description("Do not open the HTML report in the browser after export.")]
    public bool NoOpen { get; init; }

    /// <summary>
    /// Asking the run to fail on a check that was also switched off cannot be honoured: the
    /// analysis never runs, so it finds nothing and the gate passes. That reads as a clean
    /// result in CI, which is worse than no gate at all, so it is refused as a usage error.
    /// </summary>
    public override ValidationResult Validate() => (FailOn, SkipRedundant, SkipUnused) switch
    {
        (FailOn.Unused, _, true) => ValidationResult.Error(
            "--fail-on Unused cannot be combined with --skip-unused: the check would never run, and the scan would report success."),
        (FailOn.Any, _, true) => ValidationResult.Error(
            "--fail-on Any cannot be combined with --skip-unused: drop one of them so the result means what it says."),
        _ => ValidationResult.Success(),
    };
}
