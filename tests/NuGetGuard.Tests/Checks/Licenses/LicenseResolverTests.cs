using NuGetGuard.Checks.Licenses;
using NuGetGuard.Infrastructure.NuGetApi;

namespace NuGetGuard.Tests.Checks.Licenses;

public class LicenseResolverTests
{
    [Fact]
    public void BuildItems_ClassifiesRiskAndSortsWorstFirst()
    {
        var metadata = new List<PackageMetadata>
        {
            NewMetadata("Permissive.Pkg", m => m.License = "MIT"),
            NewMetadata("Copyleft.Pkg", m => m.License = "AGPL-3.0"),
            NewMetadata("Mystery.Pkg", m => m.License = "Unknown"),
            NewMetadata("Paid.Pkg", m => m.License = "Commercial"),
        };

        var licenses = LicenseResolver.BuildItems(metadata);

        licenses.Select(l => l.Package).ShouldBe(["Copyleft.Pkg", "Paid.Pkg", "Mystery.Pkg", "Permissive.Pkg"]);
        licenses.Select(l => l.Risk).ShouldBe(
            [LicenseRisk.StrongCopyleft, LicenseRisk.Proprietary, LicenseRisk.Unknown, LicenseRisk.Permissive]);
    }

    [Fact]
    public void ResolveFromUrlPatterns_NamesOnlyUnknownLicencesFromTheUrlShape()
    {
        var metadata = new List<PackageMetadata>
        {
            NewMetadata("Stated.Pkg", m =>
            {
                m.License = "Apache-2.0";
                m.LicenseUrl = "https://opensource.org/licenses/MIT";
            }),
            NewMetadata("Url.Pkg", m => m.LicenseUrl = "https://opensource.org/licenses/MIT"),
            NewMetadata("Opaque.Pkg", m => m.LicenseUrl = "https://example.com/terms"),
        };

        LicenseResolver.ResolveFromUrlPatterns(metadata);

        metadata.Select(m => m.License).ShouldBe(["Apache-2.0", "MIT", "Unknown"]);
    }

    private static PackageMetadata NewMetadata(string id, Action<PackageMetadata> configure)
    {
        var metadata = new PackageMetadata { Id = id, Version = "1.0.0", Projects = ["ProjA"] };
        configure(metadata);
        return metadata;
    }
}
