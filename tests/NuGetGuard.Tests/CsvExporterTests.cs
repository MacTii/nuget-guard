using NuGetGuard.Models;
using NuGetGuard.Reporting;

namespace NuGetGuard.Tests;

public sealed class CsvExporterTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-csv").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Export_WritesIssuesAndLicensesCsv_WithProperQuoting()
    {
        var vulnerable = new ReportItem
        {
            Category = "Vulnerable",
            Package = "Bad.Pkg",
            Version = "1.0.0",
            Severity = "High",
            Advisory = "https://example.com/advisory",
            Message = "Contains \"quotes\", commas",
        };
        vulnerable.AddProjects(["App"]);

        var report = new ScanReport
        {
            SolutionName = "X.sln",
            Vulnerable = [vulnerable],
            Licenses = [new LicenseItem("Bad.Pkg", "1.0.0", "MIT", LicenseRisk.Permissive, null, "App")],
        };

        var (issuesPath, licensesPath) = CsvExporter.Export(report, Path.Combine(_dir, "report"));

        var issuesLines = File.ReadAllLines(issuesPath);
        issuesLines[0].Should().Be("Category,Package,Version,Severity,Advisory,Message,Alternative,Projects");
        issuesLines[1].Should().Contain("\"Contains \"\"quotes\"\", commas\"");

        var licenseLines = File.ReadAllLines(licensesPath);
        licenseLines[0].Should().Be("Package,Version,License,Risk,LicenseUrl,Projects");
        licenseLines[1].Should().Be("Bad.Pkg,1.0.0,MIT,Permissive,,App");
    }

    [Fact]
    public void Export_OrdersIssuesByCategoryThenSeverity()
    {
        ReportItem Item(string category, string package, string severity)
        {
            var item = new ReportItem { Category = category, Package = package, Version = "1.0", Severity = severity };
            item.AddProjects(["App"]);
            return item;
        }

        var report = new ScanReport
        {
            SolutionName = "X.sln",
            Vulnerable = [Item("Vulnerable", "Moderate.Pkg", "Moderate"), Item("Vulnerable", "Critical.Pkg", "Critical")],
            Outdated = [Item("Outdated", "Old.Pkg", "Latest: 2.0")],
        };

        var (issuesPath, _) = CsvExporter.Export(report, Path.Combine(_dir, "report"));
        var lines = File.ReadAllLines(issuesPath);

        lines[1].Should().StartWith("Vulnerable,Critical.Pkg");
        lines[2].Should().StartWith("Vulnerable,Moderate.Pkg");
        lines[3].Should().StartWith("Outdated,Old.Pkg");
    }
}
