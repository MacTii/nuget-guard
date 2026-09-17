using NuGetGuard.Checks.Deprecations;
using NuGetGuard.Infrastructure.NuGetApi;

namespace NuGetGuard.Tests.Checks.Deprecations;

public class DeprecationCheckTests
{
    [Fact]
    public void Build_MapsMetadataAndSortsBySeverity()
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

        var deprecated = DeprecationCheck.Build(metadata);

        var item = deprecated.ShouldHaveSingleItem();
        item.Package.ShouldBe("Old.Package");
        item.Severity.ShouldBe("Legacy");
        item.Alternative.ShouldBe("New.Package [2.0.0, )");
        item.Projects.ShouldBe(["ProjA"]);
    }

    [Fact]
    public void Build_NoAlternative_LeavesAlternativeNull()
    {
        var metadata = new List<PackageMetadata>
        {
            NewMetadata("Old.Package", m => m.IsDeprecated = true),
        };

        DeprecationCheck.Build(metadata)
            .ShouldHaveSingleItem()
            .Alternative.ShouldBeNull();
    }

    private static PackageMetadata NewMetadata(string id, Action<PackageMetadata> configure)
    {
        var metadata = new PackageMetadata { Id = id, Version = "1.0.0", Projects = ["ProjA"] };
        configure(metadata);
        return metadata;
    }
}
