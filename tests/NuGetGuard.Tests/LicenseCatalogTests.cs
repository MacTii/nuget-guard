using NuGetGuard.Models;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public class LicenseCatalogTests
{
    [Theory]
    [InlineData("MIT", LicenseRisk.Permissive)]
    [InlineData("Apache-2.0", LicenseRisk.Permissive)]
    [InlineData("BSD-3-Clause", LicenseRisk.Permissive)]
    [InlineData("MS-PL", LicenseRisk.Permissive)]
    [InlineData("LGPL-2.1", LicenseRisk.WeakCopyleft)]
    [InlineData("LGPL-3.0", LicenseRisk.WeakCopyleft)]
    [InlineData("MPL-2.0", LicenseRisk.WeakCopyleft)]
    [InlineData("EPL-2.0", LicenseRisk.WeakCopyleft)]
    [InlineData("GPL-2.0", LicenseRisk.StrongCopyleft)]
    [InlineData("GPL-3.0-or-later", LicenseRisk.StrongCopyleft)]
    [InlineData("AGPL-3.0", LicenseRisk.StrongCopyleft)]
    public void GetRisk_KnownSpdxIdentifiers_AreClassified(string license, LicenseRisk expected) =>
        LicenseCatalog.GetRisk(license).Should().Be(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Unknown")]
    [InlineData("Some-Proprietary-EULA")]
    public void GetRisk_UnrecognizedValues_AreUnknown(string? license) =>
        LicenseCatalog.GetRisk(license).Should().Be(LicenseRisk.Unknown);

    [Fact]
    public void GetRisk_CompoundExpression_UsesFuzzyMatch() =>
        LicenseCatalog.GetRisk("MIT OR Apache-2.0").Should().Be(LicenseRisk.Permissive);

    [Fact]
    public void GetRisk_GplExpression_IsStrongCopyleft_ButLgplIsNot()
    {
        LicenseCatalog.GetRisk("GPL-2.0 WITH Classpath-exception").Should().Be(LicenseRisk.StrongCopyleft);
        LicenseCatalog.GetRisk("LGPL-2.1-or-later").Should().Be(LicenseRisk.WeakCopyleft);
    }

    [Theory]
    [InlineData("Newtonsoft.Json", "MIT")]
    [InlineData("newtonsoft.json", "MIT")] // case-insensitive
    [InlineData("Moq", "BSD-3-Clause")]
    [InlineData("itext7", "AGPL-3.0")]
    [InlineData("hangfire", "LGPL-3.0")]
    public void GetKnownLicense_ExactMatch_ReturnsLicense(string packageId, string expected) =>
        LicenseCatalog.GetKnownLicense(packageId).Should().Be(expected);

    [Theory]
    [InlineData("Microsoft.AspNetCore.Mvc.Core", "MIT")]         // prefix microsoft.aspnetcore.
    [InlineData("Microsoft.AspNet.SomethingNew", "Apache-2.0")]  // prefix microsoft.aspnet.
    [InlineData("AWSSDK.KinesisFirehose", "Apache-2.0")]         // prefix awssdk.
    [InlineData("Serilog.Sinks.BrandNew", "Apache-2.0")]         // prefix serilog.
    public void GetKnownLicense_PrefixMatch_ReturnsLicense(string packageId, string expected) =>
        LicenseCatalog.GetKnownLicense(packageId).Should().Be(expected);

    [Fact]
    public void GetKnownLicense_MoreSpecificPrefix_WinsOverGeneric()
    {
        // microsoft.aspnetcore. (MIT) must win over microsoft.aspnet. (Apache-2.0)
        LicenseCatalog.GetKnownLicense("Microsoft.AspNetCore.Http").Should().Be("MIT");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Some.Totally.Unknown.Package")]
    public void GetKnownLicense_Unknown_ReturnsNull(string? packageId) =>
        LicenseCatalog.GetKnownLicense(packageId).Should().BeNull();
}
