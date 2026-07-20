using NuGetGuard.Models;
using Spectre.Console;

namespace NuGetGuard.Reporting;

/// <summary>Renders the scan report to the console using Spectre.Console.</summary>
public static class ConsoleReporter
{
    public static void Render(ScanReport report)
    {
        RenderVulnerable(report);
        RenderDeprecated(report);
        RenderOutdated(report);
        RenderLicenses(report);
        RenderRedundant(report);
        RenderUnused(report);
        RenderSummary(report);
    }

    private static void RenderVulnerable(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[red bold]━━━ 🚨 VULNERABLE PACKAGES ━━━[/]");

        if (report.SkippedProjects.Count > 0)
            AnsiConsole.MarkupLine($"[yellow]⚠️  Skipped (build/restore failed): {Markup.Escape(string.Join(", ", report.SkippedProjects))}[/]");

        if (report.Vulnerable.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]✅ No vulnerable packages found.[/]");
            return;
        }

        foreach (var item in report.Vulnerable)
        {
            var color = Rankings.SeverityOrder(item.Severity) switch
            {
                0 => "red",
                1 => "maroon",
                2 => "yellow",
                _ => "white",
            };
            AnsiConsole.MarkupLine($"  [{color}]📦 {Markup.Escape(item.Package)} {Markup.Escape(item.Version)}[/]");
            AnsiConsole.MarkupLine($"     [{color}]Severity : {Markup.Escape(item.Severity ?? "")}[/]");
            if (!string.IsNullOrEmpty(item.Advisory))
                AnsiConsole.MarkupLine($"     [grey]Advisory : {Markup.Escape(item.Advisory)}[/]");
            AnsiConsole.MarkupLine($"     [grey50]Projects : {Markup.Escape(item.ProjectsDisplay)}[/]");
            AnsiConsole.WriteLine();
        }
    }

    private static void RenderDeprecated(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[yellow bold]━━━ ⚠️ DEPRECATED PACKAGES ━━━[/]");

        if (report.Deprecated.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]✅ No deprecated packages found.[/]");
            return;
        }

        foreach (var item in report.Deprecated)
        {
            AnsiConsole.MarkupLine($"  [red]📦 {Markup.Escape(item.Package)} {Markup.Escape(item.Version)}[/]");
            if (!string.IsNullOrEmpty(item.Severity))
                AnsiConsole.MarkupLine($"     [yellow]Reason      : {Markup.Escape(item.Severity)}[/]");
            if (!string.IsNullOrEmpty(item.Message))
                AnsiConsole.MarkupLine($"     [grey]Message     : {Markup.Escape(item.Message)}[/]");
            if (!string.IsNullOrEmpty(item.Alternative))
                AnsiConsole.MarkupLine($"     [cyan]Alternative : {Markup.Escape(item.Alternative)}[/]");
            AnsiConsole.MarkupLine($"     [grey50]Projects    : {Markup.Escape(item.ProjectsDisplay)}[/]");
            AnsiConsole.WriteLine();
        }
    }

    private static void RenderOutdated(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[blue bold]━━━ 📦 OUTDATED PACKAGES ━━━[/]");

        if (report.OutdatedScanFailed)
        {
            AnsiConsole.MarkupLine("[yellow]⚠️ Outdated scan failed.[/]");
            return;
        }
        if (report.Outdated.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]✅ All packages are up to date.[/]");
            return;
        }

        foreach (var item in report.Outdated)
        {
            AnsiConsole.MarkupLine($"  [teal]📦 {Markup.Escape(item.Package)} {Markup.Escape(item.Version)}[/]");
            AnsiConsole.MarkupLine($"     [cyan]{Markup.Escape(item.Severity ?? "")}[/]");
            AnsiConsole.MarkupLine($"     [grey50]Projects: {Markup.Escape(item.ProjectsDisplay)}[/]");
            AnsiConsole.WriteLine();
        }
    }

    private static void RenderLicenses(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[fuchsia bold]━━━ 📜 LICENSE AUDIT ━━━[/]");

        foreach (var risk in new[] { LicenseRisk.StrongCopyleft, LicenseRisk.WeakCopyleft, LicenseRisk.Unknown, LicenseRisk.Permissive })
        {
            var group = report.Licenses.Where(l => l.Risk == risk).OrderBy(l => l.Package, StringComparer.OrdinalIgnoreCase).ToList();
            if (group.Count == 0)
                continue;

            var (emoji, color) = risk switch
            {
                LicenseRisk.StrongCopyleft => ("🔴", "red"),
                LicenseRisk.WeakCopyleft => ("🟡", "yellow"),
                LicenseRisk.Permissive => ("🟢", "green"),
                _ => ("⚪", "grey"),
            };

            AnsiConsole.MarkupLine($"  [{color}]{emoji} {risk} ({group.Count})[/]");
            foreach (var item in group)
            {
                var urlNote = string.IsNullOrEmpty(item.LicenseUrl) ? "" : $"  → {item.LicenseUrl}";
                AnsiConsole.MarkupLine($"     [{color}]📦 {Markup.Escape(item.Package)} {Markup.Escape(item.Version)}  [[{Markup.Escape(item.License)}]]{Markup.Escape(urlNote)}[/]");
            }
            AnsiConsole.WriteLine();
        }
    }

    private static void RenderRedundant(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[fuchsia bold]━━━ 🔗 REDUNDANT PACKAGES (covered transitively) ━━━[/]");

        if (report.Redundant.Count == 0)
        {
            AnsiConsole.MarkupLine("  [green]✅ No redundant packages found.[/]");
            return;
        }

        foreach (var group in report.Redundant)
        {
            var projectType = group.IsLegacy ? "legacy ⚠️" : group.IsSdkStyle ? "SDK" : "unknown";
            AnsiConsole.MarkupLine($"  [white]📂 {Markup.Escape(group.ProjectName)}  ({projectType})[/]");

            if (group.IsLegacy)
                AnsiConsole.MarkupLine("     [yellow]⚠️  packages.config — cannot remove, informational only[/]");

            var color = group.IsLegacy ? "grey50" : "fuchsia";
            foreach (var item in group.Items)
            {
                var sourceLabel = item.CoveredBySource != "this project" ? $"  ({item.CoveredBySource})" : "";
                AnsiConsole.MarkupLine(
                    $"     [{color}]🔗 {Markup.Escape(item.Package)} {Markup.Escape(item.Version)}  ← pulled by  {Markup.Escape(item.CoveredBy)} {Markup.Escape(item.CoveredByVersion)}{Markup.Escape(sourceLabel)}[/]");
            }
            AnsiConsole.WriteLine();
        }
    }

    private static void RenderUnused(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[aqua bold]━━━ 🧹 POSSIBLY UNUSED PACKAGES ━━━[/]");

        if (report.Unused.Count == 0)
        {
            AnsiConsole.MarkupLine("  [green]✅ Every referenced package is used in source.[/]");
            return;
        }

        foreach (var group in report.Unused)
        {
            var projectType = group.IsLegacy ? "legacy ⚠️" : "SDK";
            AnsiConsole.MarkupLine($"  [white]📂 {Markup.Escape(group.ProjectName)}  ({projectType})[/]");

            foreach (var item in group.Items)
            {
                AnsiConsole.MarkupLine(
                    $"     [aqua]🧹 {Markup.Escape(item.Package)} {Markup.Escape(item.Version)}[/]  [grey50]no code references {Markup.Escape(item.Namespaces)}[/]");
            }
            AnsiConsole.WriteLine();
        }

        AnsiConsole.MarkupLine(
            "  [yellow]⚠️  Heuristic — packages used only via configuration, DI or reflection also land here. Review before removing.[/]");
    }

    private static void RenderSummary(ScanReport report)
    {
        AnsiConsole.MarkupLine("\n[cyan bold]━━━ 📊 SUMMARY ━━━[/]");
        AnsiConsole.MarkupLine($"  Vulnerable      : {(report.Vulnerable.Count > 0 ? $"🚨 {report.Vulnerable.Count}" : "✅ 0")}");
        AnsiConsole.MarkupLine($"  Deprecated      : {(report.Deprecated.Count > 0 ? $"⚠️ {report.Deprecated.Count}" : "✅ 0")}");
        AnsiConsole.MarkupLine(report.OutdatedScanFailed
            ? "  [yellow]Outdated        : ⚠️  scan failed (build errors)[/]"
            : $"  Outdated        : {(report.Outdated.Count > 0 ? $"📦 {report.Outdated.Count}" : "✅ 0")}");
        AnsiConsole.MarkupLine(
            $"  Redundant       : {(report.RedundantCount > 0 ? $"🔗 {report.RedundantCount}" : "✅ 0")}");
        AnsiConsole.MarkupLine(
            $"  Possibly unused : {(report.UnusedCount > 0 ? $"🧹 {report.UnusedCount}" : "✅ 0")}");
        AnsiConsole.MarkupLine(
            $"  Licenses total  : {report.Licenses.Count}  (🔴 StrongCopyleft: {report.StrongCopyleftCount}  ⚪ Unknown: {report.UnknownLicenseCount})");
    }
}
