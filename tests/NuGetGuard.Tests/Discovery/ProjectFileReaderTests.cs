using NuGetGuard.Services.Discovery;
using NuGetGuard.Services;

namespace NuGetGuard.Tests.Discovery;

public sealed class ProjectFileReaderTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-tests").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteFile(string relativePath, string content)
    {
        var path = Path.Combine(_dir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void ReadDirectPackages_VersionAttribute_IsParsed()
    {
        var csproj = WriteFile("App\\App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
              </ItemGroup>
            </Project>
            """);

        var packages = ProjectFileReader.ReadDirectPackages(csproj);

        packages.ShouldContainKeyAndValue("Newtonsoft.Json", "13.0.3");
    }

    [Fact]
    public void ReadDirectPackages_VersionChildElement_IsParsed()
    {
        var csproj = WriteFile("App\\App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Serilog">
                  <Version>3.1.1</Version>
                </PackageReference>
              </ItemGroup>
            </Project>
            """);

        var packages = ProjectFileReader.ReadDirectPackages(csproj);

        packages.ShouldContainKeyAndValue("Serilog", "3.1.1");
    }

    [Fact]
    public void ReadDirectPackages_WildcardVersions_AreSkipped()
    {
        var csproj = WriteFile("App\\App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Floating" Version="1.*" />
                <PackageReference Include="Pinned" Version="2.0.0" />
              </ItemGroup>
            </Project>
            """);

        var packages = ProjectFileReader.ReadDirectPackages(csproj);

        packages.ShouldNotContainKey("Floating");
        packages.ShouldContainKeyAndValue("Pinned", "2.0.0");
    }

    [Fact]
    public void ReadDirectPackages_PackagesConfig_IsMerged()
    {
        var csproj = WriteFile("Legacy\\Legacy.csproj", """
            <Project ToolsVersion="15.0">
              <ItemGroup />
            </Project>
            """);
        WriteFile("Legacy\\packages.config", """
            <?xml version="1.0" encoding="utf-8"?>
            <packages>
              <package id="log4net" version="2.0.15" targetFramework="net48" />
            </packages>
            """);

        var packages = ProjectFileReader.ReadDirectPackages(csproj);

        packages.ShouldContainKeyAndValue("log4net", "2.0.15");
    }

    [Fact]
    public void ReadDirectPackages_CentralPackageManagement_ResolvesVersionFromProps()
    {
        var csproj = WriteFile("App\\App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Polly" />
              </ItemGroup>
            </Project>
            """);
        var central = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Polly"] = "8.4.0" };

        var packages = ProjectFileReader.ReadDirectPackages(csproj, central);

        packages.ShouldContainKeyAndValue("Polly", "8.4.0");
    }

    [Fact]
    public void ReadCentralPackageVersions_ParsesDirectoryPackagesProps()
    {
        WriteFile("Directory.Packages.props", """
            <Project>
              <ItemGroup>
                <PackageVersion Include="xunit" Version="2.9.2" />
                <PackageVersion Include="Floating" Version="1.*" />
              </ItemGroup>
            </Project>
            """);

        var versions = ProjectFileReader.ReadCentralPackageVersions(_dir);

        versions.ShouldContainKeyAndValue("xunit", "2.9.2");
        versions.ShouldNotContainKey("Floating"); // wildcards skipped
    }

    [Fact]
    public void IsSdkStyleProject_DetectsSdkAttribute()
    {
        var sdk = WriteFile("Sdk\\Sdk.csproj", """<Project Sdk="Microsoft.NET.Sdk"></Project>""");
        var legacy = WriteFile("Old\\Old.csproj", """<Project ToolsVersion="15.0"></Project>""");

        ProjectFileReader.IsSdkStyleProject(new FileInfo(sdk)).ShouldBeTrue();
        ProjectFileReader.IsSdkStyleProject(new FileInfo(legacy)).ShouldBeFalse();
    }

    [Fact]
    public void IsLegacyProject_DetectsPackagesConfig()
    {
        var legacy = WriteFile("Old\\Old.csproj", """<Project ToolsVersion="15.0"></Project>""");
        WriteFile("Old\\packages.config", "<packages />");
        var sdk = WriteFile("Sdk\\Sdk.csproj", """<Project Sdk="Microsoft.NET.Sdk"></Project>""");

        ProjectFileReader.IsLegacyProject(new FileInfo(legacy)).ShouldBeTrue();
        ProjectFileReader.IsLegacyProject(new FileInfo(sdk)).ShouldBeFalse();
    }

    [Fact]
    public void GetProjectReferenceClosure_WalksTransitiveReferences_ExcludingSelf()
    {
        var libB = WriteFile("LibB\\LibB.csproj", """<Project Sdk="Microsoft.NET.Sdk"></Project>""");
        var libA = WriteFile("LibA\\LibA.csproj", """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <ProjectReference Include="..\LibB\LibB.csproj" />
              </ItemGroup>
            </Project>
            """);
        var app = WriteFile("App\\App.csproj", """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <ProjectReference Include="..\LibA\LibA.csproj" />
              </ItemGroup>
            </Project>
            """);

        var closure = ProjectFileReader.GetProjectReferenceClosure(app);

        closure.ShouldBe([Path.GetFullPath(libA), Path.GetFullPath(libB)], ignoreOrder: true);
        closure.ShouldNotContain(Path.GetFullPath(app));
    }
}
