using NuGetGuard.Models;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public sealed class LicenseOverridesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-overrides").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteMap(string content, string name = LicenseOverrides.ConventionalFileName)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static PackageMetadata Package(string id, string license = "Unknown") =>
        new() { Id = id, Version = "1.0.0", Projects = ["App"], License = license };

    [Fact]
    public void Load_ReadsIdToLicenceMap()
    {
        var path = WriteMap("""{ "Acme.Internal": "Proprietary", "Acme.Shared": "MIT" }""");

        var map = LicenseOverrides.Load(path);

        map["Acme.Internal"].ShouldBe("Proprietary");
        map["acme.shared"].ShouldBe("MIT"); // ids are case-insensitive
    }

    [Theory]
    [InlineData("{ not valid json")]
    [InlineData("")]
    public void Load_BrokenFile_ReturnsEmptyRatherThanThrowing(string content) =>
        LicenseOverrides.Load(WriteMap(content)).ShouldBeEmpty();

    [Fact]
    public void Load_MissingFile_ReturnsEmpty() =>
        LicenseOverrides.Load(Path.Combine(_dir, "does-not-exist.json")).ShouldBeEmpty();

    [Fact]
    public void Apply_SetsLicenceAndCountsMatches()
    {
        var packages = new List<PackageMetadata> { Package("Acme.Internal"), Package("Newtonsoft.Json", "MIT") };
        var map = LicenseOverrides.Load(WriteMap("""{ "Acme.Internal": "Proprietary" }"""));

        LicenseOverrides.Apply(packages, map).ShouldBe(1);

        packages[0].License.ShouldBe("Proprietary");
        packages[1].License.ShouldBe("MIT"); // untouched
    }

    [Fact]
    public void Apply_OverridesEvenAnAlreadyIdentifiedLicence()
    {
        // The team's own declaration beats the feed's metadata, which can be wrong.
        var packages = new List<PackageMetadata> { Package("Some.Package", "MIT") };
        var map = LicenseOverrides.Load(WriteMap("""{ "Some.Package": "Commercial" }"""));

        LicenseOverrides.Apply(packages, map).ShouldBe(1);
        packages[0].License.ShouldBe("Commercial");
        LicenseCatalog.GetRisk(packages[0].License).ShouldBe(LicenseRisk.Proprietary);
    }

    [Fact]
    public void Apply_BlankLicenceIsIgnored()
    {
        var packages = new List<PackageMetadata> { Package("Acme.Internal") };
        var map = LicenseOverrides.Load(WriteMap("""{ "Acme.Internal": "  " }"""));

        LicenseOverrides.Apply(packages, map).ShouldBe(0);
        packages[0].License.ShouldBe("Unknown");
    }

    [Fact]
    public void Locate_PrefersExplicitPathOverConvention()
    {
        WriteMap("""{ "A": "MIT" }""");
        var custom = WriteMap("""{ "B": "MIT" }""", "custom.json");

        LicenseOverrides.Locate(custom, _dir).ShouldBe(custom);
    }

    [Fact]
    public void Locate_FindsConventionalFileBesideSolution()
    {
        var conventional = WriteMap("""{ "A": "MIT" }""");

        LicenseOverrides.Locate(null, _dir).ShouldBe(conventional);
    }

    [Fact]
    public void Locate_NothingToUse_ReturnsNull() =>
        LicenseOverrides.Locate(null, _dir).ShouldBeNull();
}
