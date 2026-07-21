using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public sealed class PackageCollectorTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-collector").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteFile(string relativePath, string content)
    {
        var path = Path.Combine(_dir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void CollectPackages_StaleVersionInPackagesFolder_IsNotReported()
    {
        // A long-lived legacy solution keeps folders from earlier restores. Only packages.config counts.
        var solutionPath = WriteFile("App.sln", "");
        var projectPath = WriteFile("App\\App.csproj", """<Project ToolsVersion="15.0"><ItemGroup /></Project>""");
        WriteFile("App\\packages.config", """
            <?xml version="1.0" encoding="utf-8"?>
            <packages>
              <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
            </packages>
            """);
        Directory.CreateDirectory(Path.Combine(_dir, "packages", "Newtonsoft.Json.13.0.3"));
        Directory.CreateDirectory(Path.Combine(_dir, "packages", "Newtonsoft.Json.9.0.1")); // stale leftover

        var context = new SolutionContext(new FileInfo(solutionPath), [new FileInfo(projectPath)]);
        var packages = PackageCollector.CollectPackages(context);

        packages.Values.Select(p => $"{p.Id} {p.Version}").ShouldBe(["Newtonsoft.Json 13.0.3"]);
    }

    [Fact]
    public void CollectPackages_PackagesOfOtherProjects_AreNotAttributedToEveryProject()
    {
        var solutionPath = WriteFile("App.sln", "");

        var firstPath = WriteFile("First\\First.csproj", """<Project ToolsVersion="15.0"><ItemGroup /></Project>""");
        WriteFile("First\\packages.config", """
            <packages><package id="OnlyInFirst" version="1.0.0" targetFramework="net48" /></packages>
            """);

        var secondPath = WriteFile("Second\\Second.csproj", """<Project ToolsVersion="15.0"><ItemGroup /></Project>""");
        WriteFile("Second\\packages.config", """
            <packages><package id="OnlyInSecond" version="2.0.0" targetFramework="net48" /></packages>
            """);

        // The packages folder is solution-wide and holds both
        Directory.CreateDirectory(Path.Combine(_dir, "packages", "OnlyInFirst.1.0.0"));
        Directory.CreateDirectory(Path.Combine(_dir, "packages", "OnlyInSecond.2.0.0"));

        var context = new SolutionContext(
            new FileInfo(solutionPath), [new FileInfo(firstPath), new FileInfo(secondPath)]);
        var packages = PackageCollector.CollectPackages(context);

        packages.Values.Single(p => p.Id == "OnlyInFirst").Projects.ShouldBe(["First"]);
        packages.Values.Single(p => p.Id == "OnlyInSecond").Projects.ShouldBe(["Second"]);
    }
}
