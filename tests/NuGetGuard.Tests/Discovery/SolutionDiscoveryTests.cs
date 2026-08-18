using NuGetGuard.Services.Discovery;
using NuGetGuard.Services;

namespace NuGetGuard.Tests.Discovery;

public sealed class SolutionDiscoveryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-discovery").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private void WriteFile(string relativePath, string content = "")
    {
        var path = Path.Combine(_dir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    [Fact]
    public void Discover_FindsSolutionAndProjects_IgnoringBinObj()
    {
        WriteFile("MyApp.sln");
        WriteFile("App\\App.csproj", """<Project Sdk="Microsoft.NET.Sdk"></Project>""");
        WriteFile("App\\bin\\Debug\\Generated.csproj", "<Project></Project>");

        var context = SolutionDiscovery.Discover(_dir);

        context.ShouldNotBeNull();
        context.SolutionFile.Name.ShouldBe("MyApp.sln");
        context.ProjectFiles.ShouldHaveSingleItem().Name.ShouldBe("App.csproj");
    }

    [Fact]
    public void Discover_FindsSlnxSolutions()
    {
        WriteFile("Modern.slnx", "<Solution />");
        WriteFile("App\\App.csproj", """<Project Sdk="Microsoft.NET.Sdk"></Project>""");

        var context = SolutionDiscovery.Discover(_dir);

        context.ShouldNotBeNull();
        context.SolutionFile.Name.ShouldBe("Modern.slnx");
    }

    [Fact]
    public void Discover_NoSolution_ReturnsNull()
    {
        WriteFile("App\\App.csproj", """<Project Sdk="Microsoft.NET.Sdk"></Project>""");

        SolutionDiscovery.Discover(_dir).ShouldBeNull();
    }

    [Fact]
    public void Discover_MissingDirectory_ReturnsNull() =>
        SolutionDiscovery.Discover(Path.Combine(_dir, "does-not-exist")).ShouldBeNull();
}
