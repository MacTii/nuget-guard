using NuGetGuard.Services.Packages;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public class AssemblyNamespaceReaderTests
{
    private static string ToolAssemblyPath =>
        Path.Combine(AppContext.BaseDirectory, "NuGetGuard.dll");

    [Fact]
    public void ReadPublicNamespaces_RealAssembly_ReturnsItsNamespaces()
    {
        var namespaces = AssemblyNamespaceReader.ReadPublicNamespaces(ToolAssemblyPath);

        namespaces.ShouldContain("NuGetGuard.Models");
        namespaces.ShouldContain("NuGetGuard.Services");
    }

    [Fact]
    public void ReadPublicNamespaces_MissingFile_ReturnsEmpty() =>
        AssemblyNamespaceReader.ReadPublicNamespaces(
            Path.Combine(AppContext.BaseDirectory, "does-not-exist.dll")).ShouldBeEmpty();

    [Fact]
    public void ReadPublicNamespaces_NonAssemblyFile_ReturnsEmpty()
    {
        var path = Path.Combine(Path.GetTempPath(), $"not-an-assembly-{Guid.NewGuid():N}.dll");
        File.WriteAllText(path, "this is not a PE file");

        try
        {
            AssemblyNamespaceReader.ReadPublicNamespaces(path).ShouldBeEmpty();
        }
        finally
        {
            File.Delete(path);
        }
    }
}
