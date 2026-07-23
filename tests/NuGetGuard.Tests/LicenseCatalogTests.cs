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
        LicenseCatalog.GetRisk(license).ShouldBe(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Unknown")]
    [InlineData("Some-Unrecognised-Text")]
    public void GetRisk_UnrecognizedValues_AreUnknown(string? license) =>
        LicenseCatalog.GetRisk(license).ShouldBe(LicenseRisk.Unknown);

    [Theory]
    [InlineData("Commercial")]
    [InlineData("MS-EULA")]
    public void GetRisk_NamedNonOpenSourceLicences_AreProprietary(string license) =>
        LicenseCatalog.GetRisk(license).ShouldBe(LicenseRisk.Proprietary);

    [Fact]
    public void GetRisk_CompoundExpression_UsesFuzzyMatch() =>
        LicenseCatalog.GetRisk("MIT OR Apache-2.0").ShouldBe(LicenseRisk.Permissive);

    [Theory]
    // "OR" means the licensee picks any one term, so the most permissive wins
    [InlineData("MIT OR GPL-3.0-only", LicenseRisk.Permissive)]
    [InlineData("GPL-2.0-or-later OR LGPL-2.1-or-later OR MPL-1.1", LicenseRisk.WeakCopyleft)]
    [InlineData("Apache-2.0 OR MIT", LicenseRisk.Permissive)]
    public void GetRisk_DisjunctiveExpression_TakesMostPermissive(string license, LicenseRisk expected) =>
        LicenseCatalog.GetRisk(license).ShouldBe(expected);

    [Theory]
    // "AND" means every term applies, so the most restrictive wins
    [InlineData("MIT AND GPL-3.0-only", LicenseRisk.StrongCopyleft)]
    [InlineData("Apache-2.0 AND MPL-2.0", LicenseRisk.WeakCopyleft)]
    public void GetRisk_ConjunctiveExpression_TakesMostRestrictive(string license, LicenseRisk expected) =>
        LicenseCatalog.GetRisk(license).ShouldBe(expected);

    [Fact]
    public void GetRisk_Mpl11_IsWeakCopyleft() =>
        LicenseCatalog.GetRisk("MPL-1.1").ShouldBe(LicenseRisk.WeakCopyleft);

    [Fact]
    public void GetRisk_GplExpression_IsStrongCopyleft_ButLgplIsNot()
    {
        LicenseCatalog.GetRisk("GPL-2.0 WITH Classpath-exception").ShouldBe(LicenseRisk.StrongCopyleft);
        LicenseCatalog.GetRisk("LGPL-2.1-or-later").ShouldBe(LicenseRisk.WeakCopyleft);
    }

    [Theory]
    [InlineData("Newtonsoft.Json", "MIT")]
    [InlineData("newtonsoft.json", "MIT")] // case-insensitive
    [InlineData("Moq", "BSD-3-Clause")]
    [InlineData("itext7", "AGPL-3.0")]
    [InlineData("hangfire", "LGPL-3.0")]
    [InlineData("EntityFramework", "MIT")]
    [InlineData("UTF.Unknown", "MPL-1.1")]
    public void GetKnownLicense_ExactMatch_ReturnsLicense(string packageId, string expected) =>
        LicenseCatalog.GetKnownLicense(packageId).ShouldBe(expected);

    [Fact]
    public void GetKnownLicense_CkEditor_IsTriLicensedWeakCopyleft()
    {
        var license = LicenseCatalog.GetKnownLicense("ckeditor-full");
        license.ShouldNotBeNull();
        LicenseCatalog.GetRisk(license).ShouldBe(LicenseRisk.WeakCopyleft);
    }

    [Theory]
    [InlineData("Microsoft.AspNetCore.Mvc.Core", "MIT")]         // prefix microsoft.aspnetcore.
    [InlineData("Microsoft.AspNet.SomethingNew", "Apache-2.0")]  // prefix microsoft.aspnet.
    [InlineData("AWSSDK.KinesisFirehose", "Apache-2.0")]         // prefix awssdk.
    [InlineData("Serilog.Sinks.BrandNew", "Apache-2.0")]         // prefix serilog.
    public void GetKnownLicense_PrefixMatch_ReturnsLicense(string packageId, string expected) =>
        LicenseCatalog.GetKnownLicense(packageId).ShouldBe(expected);

    [Fact]
    public void GetKnownLicense_MoreSpecificPrefix_WinsOverGeneric()
    {
        // microsoft.aspnetcore. (MIT) must win over microsoft.aspnet. (Apache-2.0)
        LicenseCatalog.GetKnownLicense("Microsoft.AspNetCore.Http").ShouldBe("MIT");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Some.Totally.Unknown.Package")]
    public void GetKnownLicense_Unknown_ReturnsNull(string? packageId) =>
        LicenseCatalog.GetKnownLicense(packageId).ShouldBeNull();
}
