using NuGetGuard.Services.Packages;
using NuGetGuard.Services;

namespace NuGetGuard.Tests.Packages;

public sealed class NuspecDependencyReaderTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-nuspec").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WritePackage(string id, string version, string nuspecBody)
    {
        var packagesFolder = Path.Combine(_dir, "packages");
        var packageDir = Path.Combine(packagesFolder, $"{id}.{version}");
        Directory.CreateDirectory(packageDir);
        File.WriteAllText(Path.Combine(packageDir, $"{id}.nuspec"), nuspecBody);
        return packagesFolder;
    }

    [Fact]
    public void ReadDependencies_ReturnsIdAndVersionRange()
    {
        var packages = WritePackage("WebGrease", "1.6.0", """
            <package><metadata><id>WebGrease</id><version>1.6.0</version>
              <dependencies>
                <dependency id="Antlr" version="[3.4.1.9004, )" />
                <dependency id="Newtonsoft.Json" version="[5.0.4, )" />
              </dependencies>
            </metadata></package>
            """);

        var deps = NuspecDependencyReader.ReadDependencies(packages, "WebGrease", "1.6.0");

        deps.ShouldContain(d => d.Id == "Antlr" && d.VersionRange == "[3.4.1.9004, )");
        deps.ShouldContain(d => d.Id == "Newtonsoft.Json" && d.VersionRange == "[5.0.4, )");
    }

    [Fact]
    public void ReadDependencies_MissingVersionAttribute_YieldsNullRange()
    {
        var packages = WritePackage("Sample", "1.0.0", """
            <package><metadata><id>Sample</id><version>1.0.0</version>
              <dependencies><dependency id="SomeDep" /></dependencies>
            </metadata></package>
            """);

        var dep = NuspecDependencyReader.ReadDependencies(packages, "Sample", "1.0.0").ShouldHaveSingleItem();
        dep.Id.ShouldBe("SomeDep");
        dep.VersionRange.ShouldBeNull();
    }

    [Fact]
    public void ReadDependencyIds_StillReturnsBareIds()
    {
        var packages = WritePackage("Sample", "1.0.0", """
            <package><metadata><id>Sample</id><version>1.0.0</version>
              <dependencies><dependency id="A" version="[1.0, )" /><dependency id="B" version="2.0" /></dependencies>
            </metadata></package>
            """);

        NuspecDependencyReader.ReadDependencyIds(packages, "Sample", "1.0.0").ShouldBe(["A", "B"], ignoreOrder: true);
    }
}
