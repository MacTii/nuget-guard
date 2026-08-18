using NuGetGuard.Services.Discovery;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public sealed class SolutionProjectReaderTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-slnreader").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteFile(string relativePath, string content)
    {
        var path = Path.Combine(_dir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void ReadProjects_Sln_ReturnsOnlyListedExistingProjects()
    {
        WriteFile("App\\App.csproj", "<Project />");
        WriteFile("Lib\\Lib.csproj", "<Project />");
        WriteFile("Unrelated\\Unrelated.csproj", "<Project />"); // on disk but not in the solution
        var sln = WriteFile("MyApp.sln", """
            Microsoft Visual Studio Solution File, Format Version 12.00
            Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "App\App.csproj", "{11111111-1111-1111-1111-111111111111}"
            EndProject
            Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Lib", "Lib\Lib.csproj", "{22222222-2222-2222-2222-222222222222}"
            EndProject
            Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "Solution Items", "Solution Items", "{33333333-3333-3333-3333-333333333333}"
            EndProject
            """);

        var projects = SolutionProjectReader.ReadProjects(new FileInfo(sln));

        projects.Select(p => p.Name).ShouldBe(["App.csproj", "Lib.csproj"], ignoreOrder: true);
    }

    [Fact]
    public void ReadProjects_Slnx_ReturnsListedProjects()
    {
        WriteFile("App\\App.csproj", "<Project />");
        WriteFile("Unrelated\\Unrelated.csproj", "<Project />");
        var slnx = WriteFile("MyApp.slnx", """
            <Solution>
              <Project Path="App/App.csproj" />
            </Solution>
            """);

        var projects = SolutionProjectReader.ReadProjects(new FileInfo(slnx));

        projects.ShouldHaveSingleItem().Name.ShouldBe("App.csproj");
    }

    [Fact]
    public void ReadProjects_ProjectListedButMissingOnDisk_IsSkipped()
    {
        var sln = WriteFile("MyApp.sln", """
            Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Gone", "Gone\Gone.csproj", "{11111111-1111-1111-1111-111111111111}"
            EndProject
            """);

        SolutionProjectReader.ReadProjects(new FileInfo(sln)).ShouldBeEmpty();
    }

    [Fact]
    public void Discover_MultipleSolutions_ScansOnlyTheChosenOne()
    {
        WriteFile("First\\First.csproj", "<Project />");
        WriteFile("First\\First.sln", """
            Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "First", "First.csproj", "{11111111-1111-1111-1111-111111111111}"
            EndProject
            """);
        WriteFile("Second\\Second.csproj", "<Project />");
        WriteFile("Second\\Second.sln", """
            Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Second", "Second.csproj", "{22222222-2222-2222-2222-222222222222}"
            EndProject
            """);

        var context = SolutionDiscovery.Discover(_dir);

        context.ShouldNotBeNull();
        context.ProjectFiles.ShouldHaveSingleItem();
        context.OtherSolutions.ShouldHaveSingleItem();
    }

    [Fact]
    public void Discover_EmptySolution_FallsBackToProjectsUnderSolutionFolder()
    {
        WriteFile("Src\\App\\App.csproj", "<Project />");
        WriteFile("Src\\Empty.sln", "Microsoft Visual Studio Solution File, Format Version 12.00");
        WriteFile("Outside\\Outside.csproj", "<Project />"); // sibling of the solution folder

        var context = SolutionDiscovery.Discover(_dir);

        context.ShouldNotBeNull();
        context.ProjectFiles.ShouldHaveSingleItem().Name.ShouldBe("App.csproj");
    }
}
