using System.Text;
using NuGetGuard.Models;

namespace NuGetGuard.Reporting;

public static class CsvExporter
{
    /// <summary>Writes the issues CSV and the licenses CSV. Returns both file paths.</summary>
    public static (string IssuesPath, string LicensesPath) Export(ScanReport report, string outputFile)
    {
        var flat = report.Vulnerable.Concat(report.Deprecated).Concat(report.Outdated).ToList();

        var sorted = flat
            .OrderBy(r => Rankings.CategoryOrder(r.Category))
            .ThenBy(r => Rankings.MaxSeverityForPackage(flat, r.Category, r.Package))
            .ThenBy(r => r.Package, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => Rankings.SeverityOrder(r.Severity));

        var issuesPath = $"{outputFile}.csv";
        var issues = new StringBuilder();
        issues.AppendLine("Category,Package,Version,Severity,Advisory,Message,Alternative,Projects");
        foreach (var row in sorted)
        {
            issues.AppendLine(Line(row.Category, row.Package, row.Version, row.Severity,
                row.Advisory, row.Message, row.Alternative, row.ProjectsDisplay));
        }
        File.WriteAllText(issuesPath, issues.ToString(), Encoding.UTF8);

        var licensesPath = $"{outputFile}-licenses.csv";
        var licenses = new StringBuilder();
        licenses.AppendLine("Package,Version,License,Risk,LicenseUrl,Projects");
        foreach (var row in report.Licenses
                     .OrderBy(l => (int)l.Risk)
                     .ThenBy(l => l.Package, StringComparer.OrdinalIgnoreCase))
        {
            licenses.AppendLine(Line(row.Package, row.Version, row.License, row.Risk.ToString(),
                row.LicenseUrl, row.Projects));
        }
        File.WriteAllText(licensesPath, licenses.ToString(), Encoding.UTF8);

        return (issuesPath, licensesPath);
    }

    private static string Line(params string?[] values) =>
        string.Join(",", values.Select(Quote));

    private static string Quote(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        var needsQuoting = value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r');
        return needsQuoting ? $"\"{value.Replace("\"", "\"\"")}\"" : value;
    }
}
