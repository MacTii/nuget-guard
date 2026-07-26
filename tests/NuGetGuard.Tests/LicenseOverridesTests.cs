using NuGetGuard.Models;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public sealed class LicenseOverridesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-overrides").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private void WriteMap(string content) =>
        File.WriteAllText(Path.Combine(_dir, LicenseOverrides.FileName), content);

    private static PackageMetadata Package(string id, string license = "Unknown") =>
        new() { Id = id, Version = "1.0.0", Projects = ["App"], License = license };

    [Fact]
    public void Load_ReadsIdToLicenceMap()
    {
        WriteMap("""{ "Acme.Internal": "Proprietary", "Acme.Shared": "MIT" }""");

        var map = LicenseOverrides.Load(_dir);

        map["Acme.Internal"].ShouldBe("Proprietary");
        map["acme.shared"].ShouldBe("MIT"); // ids are case-insensitive
    }

    [Theory]
    [InlineData("{ not valid json")]
    [InlineData("")]
    public void Load_BrokenFile_ReturnsEmptyRatherThanThrowing(string content)
    {
        WriteMap(content);

        LicenseOverrides.Load(_dir).ShouldBeEmpty();
    }

    [Fact]
    public void Load_NoFileBesideSolution_ReturnsEmpty() =>
        LicenseOverrides.Load(_dir).ShouldBeEmpty();

    [Fact]
    public void Apply_SetsLicenceAndCountsMatches()
    {
        WriteMap("""{ "Acme.Internal": "Proprietary" }""");
        var packages = new List<PackageMetadata> { Package("Acme.Internal"), Package("Newtonsoft.Json", "MIT") };

        LicenseOverrides.Apply(packages, LicenseOverrides.Load(_dir)).ShouldBe(1);

        packages[0].License.ShouldBe("Proprietary");
        packages[1].License.ShouldBe("MIT"); // untouched
    }

    [Fact]
    public void Apply_OverridesEvenAnAlreadyIdentifiedLicence()
    {
        // The team's own declaration beats the feed's metadata, which can be wrong.
        WriteMap("""{ "Some.Package": "Commercial" }""");
        var packages = new List<PackageMetadata> { Package("Some.Package", "MIT") };

        LicenseOverrides.Apply(packages, LicenseOverrides.Load(_dir)).ShouldBe(1);

        packages[0].License.ShouldBe("Commercial");
        LicenseCatalog.GetRisk(packages[0].License).ShouldBe(LicenseRisk.Proprietary);
    }

    [Fact]
    public void Apply_BlankLicenceIsIgnored()
    {
        WriteMap("""{ "Acme.Internal": "  " }""");
        var packages = new List<PackageMetadata> { Package("Acme.Internal") };

        LicenseOverrides.Apply(packages, LicenseOverrides.Load(_dir)).ShouldBe(0);
        packages[0].License.ShouldBe("Unknown");
    }
}
