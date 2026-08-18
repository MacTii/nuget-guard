using NuGetGuard.Services.Analysis;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public sealed class SourceNamespaceScannerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-scanner").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteFile(string name, string content)
    {
        var path = Path.Combine(_dir, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void ScanFiles_UsingDirective_AddsNamespaceAndItsPrefixes()
    {
        var file = WriteFile("Program.cs", "using Serilog.Sinks.File;\n");

        var used = SourceNamespaceScanner.ScanFiles([file]);

        used.ShouldContain("Serilog");
        used.ShouldContain("Serilog.Sinks");
        used.ShouldContain("Serilog.Sinks.File");
    }

    [Fact]
    public void ScanFiles_SingleSegmentUsing_IsCaptured()
    {
        var file = WriteFile("Program.cs", "using Dapper;\n");

        SourceNamespaceScanner.ScanFiles([file]).ShouldContain("Dapper");
    }

    [Theory]
    [InlineData("global using System.Text.Json;")]
    [InlineData("using static Newtonsoft.Json.JsonConvert;")]
    [InlineData("using Json = Newtonsoft.Json;")]
    public void ScanFiles_UsingVariants_AreCaptured(string line)
    {
        var file = WriteFile("Program.cs", line);

        var used = SourceNamespaceScanner.ScanFiles([file]);

        used.ShouldContain(line.Contains("System.Text.Json") ? "System.Text.Json" : "Newtonsoft.Json");
    }

    [Fact]
    public void ScanFiles_FullyQualifiedUsage_WithoutUsing_IsCaptured()
    {
        var file = WriteFile("Program.cs", "var x = Newtonsoft.Json.JsonConvert.SerializeObject(null);");

        var used = SourceNamespaceScanner.ScanFiles([file]);

        used.ShouldContain("Newtonsoft");
        used.ShouldContain("Newtonsoft.Json");
    }

    [Fact]
    public void ScanFiles_RazorAndVbImports_AreCaptured()
    {
        var razor = WriteFile("View.cshtml", "@using System.Web.Mvc\n<p>hi</p>");
        var vb = WriteFile("Module.vb", "Imports Microsoft.VisualBasic");

        var used = SourceNamespaceScanner.ScanFiles([razor, vb]);

        used.ShouldContain("System.Web.Mvc");
        used.ShouldContain("Microsoft.VisualBasic");
    }

    [Fact]
    public void ScanFiles_UnrelatedNamespace_IsNotReported()
    {
        var file = WriteFile("Program.cs", "using System;\n");

        SourceNamespaceScanner.ScanFiles([file]).ShouldNotContain("Dapper");
    }

    [Fact]
    public void EnumerateSourceFiles_SkipsBuildOutput()
    {
        WriteFile("Program.cs", "");
        WriteFile("View.cshtml", "");
        WriteFile("bin\\Debug\\Generated.cs", "");
        WriteFile("obj\\Debug\\AssemblyInfo.cs", "");
        WriteFile("readme.txt", "");

        var files = SourceNamespaceScanner.EnumerateSourceFiles(_dir).Select(Path.GetFileName).ToList();

        files.ShouldBe(["Program.cs", "View.cshtml"], ignoreOrder: true);
    }
}
