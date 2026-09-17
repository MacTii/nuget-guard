using NuGetGuard.Checks.Licenses;
using NuGetGuard.Reporting;

namespace NuGetGuard.Tests.Reporting;

public class ScanReportTests
{
    [Fact]
    public void CountsStrongCopyleftAndUnknownLicenses()
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
}
