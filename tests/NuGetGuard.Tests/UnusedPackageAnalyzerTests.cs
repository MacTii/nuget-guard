using NuGetGuard.Models;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public sealed class UnusedPackageAnalyzerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-unused").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Builds a legacy solution whose only package ships the tool's own assembly.</summary>
    private SolutionContext BuildSolution(string programContents, string projectContents = """<Project ToolsVersion="15.0"><ItemGroup /></Project>""")
    {
        var solutionPath = Path.Combine(_dir, "Sample.sln");
        File.WriteAllText(solutionPath, "");

        var projectDir = Path.Combine(_dir, "App");
        Directory.CreateDirectory(projectDir);

        var projectPath = Path.Combine(projectDir, "App.csproj");
        File.WriteAllText(projectPath, projectContents);
        File.WriteAllText(Path.Combine(projectDir, "packages.config"), """
            <?xml version="1.0" encoding="utf-8"?>
            <packages>
              <package id="FakePkg" version="1.0.0" targetFramework="net48" />
            </packages>
            """);
        File.WriteAllText(Path.Combine(projectDir, "Program.cs"), programContents);

        var libDir = Path.Combine(_dir, "packages", "FakePkg.1.0.0", "lib", "net48");
        Directory.CreateDirectory(libDir);
        File.Copy(
            Path.Combine(AppContext.BaseDirectory, "NuGetGuard.dll"),
            Path.Combine(libDir, "FakePkg.dll"));

        return new SolutionContext(new FileInfo(solutionPath), [new FileInfo(projectPath)]);
    }

    private static List<UnusedProjectGroup> Analyze(SolutionContext solution) =>
        new UnusedPackageAnalyzer().Analyze(solution, ct: TestContext.Current.CancellationToken);

    [Fact]
    public void Analyze_PackageNamespacesNeverReferenced_ReportsPackage()
    {
        var solution = BuildSolution("using System;\n\nclass Program { static void Main() { } }");

        var groups = Analyze(solution);

        var group = groups.ShouldHaveSingleItem();
        group.ProjectName.ShouldBe("App");
        group.IsLegacy.ShouldBeTrue();
        var item = group.Items.ShouldHaveSingleItem();
        item.Package.ShouldBe("FakePkg");
        item.Version.ShouldBe("1.0.0");
        item.Namespaces.ShouldContain("NuGetGuard");
    }

    [Fact]
    public void Analyze_PackageNamespaceReferenced_ReportsNothing()
    {
        var solution = BuildSolution("using NuGetGuard.Services;\n\nclass Program { static void Main() { } }");

        Analyze(solution).ShouldBeEmpty();
    }

    [Fact]
    public void Analyze_FullyQualifiedUsage_CountsAsUsed()
    {
        var solution = BuildSolution("class Program { static void Main() { var x = NuGetGuard.Models.LicenseRisk.Permissive; } }");

        Analyze(solution).ShouldBeEmpty();
    }

    [Fact]
    public void Analyze_GlobalUsingInProjectFile_CountsAsUsed()
    {
        var solution = BuildSolution(
            "class Program { static void Main() { } }",
            """
            <Project ToolsVersion="15.0">
              <ItemGroup>
                <Using Include="NuGetGuard.Services" />
              </ItemGroup>
            </Project>
            """);

        Analyze(solution).ShouldBeEmpty();
    }

    [Fact]
    public void Analyze_LegacyProjectWithoutRestoredPackagesFolder_IsSkipped()
    {
        var solution = BuildSolution("using System;\n\nclass Program { static void Main() { } }");

        // Without the restored packages/ folder the transitive filter cannot run,
        // so every packages.config entry would look unused.
        Directory.Delete(Path.Combine(_dir, "packages"), recursive: true);

        Analyze(solution).ShouldBeEmpty();
    }

    [Fact]
    public void Analyze_ProjectWithoutSource_IsSkipped()
    {
        var solution = BuildSolution("");

        Analyze(solution).ShouldBeEmpty();
    }
}
