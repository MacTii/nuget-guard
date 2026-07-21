using NuGetGuard.Models;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public class ReportBuilderTests
{
    [Fact]
    public void BuildDeprecated_MapsMetadataAndSortsBySeverity()
    {
        var metadata = new List<PackageMetadata>
        {
            NewMetadata("Old.Package", m =>
            {
                m.IsDeprecated = true;
                m.DeprecationReasons = "Legacy";
                m.DeprecationMessage = "Use the new one";
                m.AlternativeId = "New.Package";
                m.AlternativeRange = "[2.0.0, )";
            }),
            NewMetadata("Fine.Package", _ => { }),
        };

        var deprecated = ReportBuilder.BuildDeprecated(metadata);

        var item = deprecated.ShouldHaveSingleItem();
        item.Package.ShouldBe("Old.Package");
        item.Severity.ShouldBe("Legacy");
        item.Alternative.ShouldBe("New.Package [2.0.0, )");
        item.Projects.ShouldBe(["ProjA"]);
    }

    [Fact]
    public void BuildDeprecated_NoAlternative_LeavesAlternativeNull()
    {
        var metadata = new List<PackageMetadata>
        {
            NewMetadata("Old.Package", m => m.IsDeprecated = true),
        };

        ReportBuilder.BuildDeprecated(metadata)
            .ShouldHaveSingleItem()
            .Alternative.ShouldBeNull();
    }

    [Fact]
    public void BuildLicenses_ClassifiesRiskAndSortsWorstFirst()
    {
        var metadata = new List<PackageMetadata>
        {
            NewMetadata("Permissive.Pkg", m => m.License = "MIT"),
            NewMetadata("Copyleft.Pkg", m => m.License = "AGPL-3.0"),
            NewMetadata("Mystery.Pkg", m => m.License = "Unknown"),
            NewMetadata("Paid.Pkg", m => m.License = "Commercial"),
        };

        var licenses = ReportBuilder.BuildLicenses(metadata);

        licenses.Select(l => l.Package).ShouldBe(["Copyleft.Pkg", "Paid.Pkg", "Mystery.Pkg", "Permissive.Pkg"]);
        licenses.Select(l => l.Risk).ShouldBe(
            [LicenseRisk.StrongCopyleft, LicenseRisk.Proprietary, LicenseRisk.Unknown, LicenseRisk.Permissive]);
    }

    [Fact]
    public void ScanReport_CountsStrongCopyleftAndUnknownLicenses()
    {
        var report = new ScanReport
        {
            SolutionName = "X.sln",
            Licenses =
            [
                new LicenseItem("A", "1.0", "GPL-3.0", LicenseRisk.StrongCopyleft, null, "P"),
                new LicenseItem("B", "1.0", "MIT", LicenseRisk.Permissive, null, "P"),
                new LicenseItem("C", "1.0", "Unknown", LicenseRisk.Unknown, null, "P"),
            ],
        };

        report.StrongCopyleftCount.ShouldBe(1);
        report.UnknownLicenseCount.ShouldBe(1);
    }

    [Fact]
    public void ReportItem_AddProjects_DeduplicatesCaseInsensitively()
    {
        var item = new ReportItem { Category = "Vulnerable", Package = "P", Version = "1.0" };

        item.AddProjects(["App", "app", "Worker", ""]);

        item.Projects.ShouldBe(["App", "Worker"]);
        item.ProjectsDisplay.ShouldBe("App, Worker");
    }

    private static PackageMetadata NewMetadata(string id, Action<PackageMetadata> configure)
    {
        var metadata = new PackageMetadata { Id = id, Version = "1.0.0", Projects = ["ProjA"] };
        configure(metadata);
        return metadata;
    }
}
