using System.Diagnostics;
using NuGetGuard.Models;
using Spectre.Console;

namespace NuGetGuard.Reporting;

/// <summary>Dispatches export to the chosen format and optionally opens the HTML report.</summary>
public static class ReportExporter
{
    public static void Export(ScanReport report, ExportFormat format, string outputFile, bool openHtml)
    {
        switch (format)
        {
            case ExportFormat.Csv:
                var (issuesPath, licensesPath) = CsvExporter.Export(report, outputFile);
                AnsiConsole.MarkupLine($"\n[green]💾 CSV saved       : {Markup.Escape(Path.GetFullPath(issuesPath))}[/]");
                AnsiConsole.MarkupLine($"[green]💾 License CSV     : {Markup.Escape(Path.GetFullPath(licensesPath))}[/]");
                break;

            case ExportFormat.Html:
                var htmlPath = HtmlExporter.Export(report, outputFile);
                AnsiConsole.MarkupLine($"\n[green]💾 HTML saved: {Markup.Escape(Path.GetFullPath(htmlPath))}[/]");
                if (openHtml)
                    TryOpenInBrowser(htmlPath);
                break;
        }
    }

    private static void TryOpenInBrowser(string htmlPath)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Path.GetFullPath(htmlPath)) { UseShellExecute = true });
        }
        catch
        {
            // headless environment — report is still on disk
        }
    }
}
