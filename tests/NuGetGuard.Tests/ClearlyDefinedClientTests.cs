using System.Reflection;
using NuGetGuard.Services.ClearlyDefined;

namespace NuGetGuard.Tests;

public class ClearlyDefinedClientTests
{
    // ClearlyDefined marks "no usable data" with sentinel tokens; those must not become licences.
    private static string? Clean(string? declared)
    {
        var method = typeof(ClearlyDefinedClient)
            .GetMethod("Clean", BindingFlags.NonPublic | BindingFlags.Static)!;
        return (string?)method.Invoke(null, [declared]);
    }

    [Theory]
    [InlineData("MIT", "MIT")]
    [InlineData("LGPL-3.0", "LGPL-3.0")]
    [InlineData("MIT OR BSD-3-Clause", "MIT OR BSD-3-Clause")]
    [InlineData("  MPL-1.1  ", "MPL-1.1")]
    public void Clean_UsableSpdx_IsKept(string declared, string expected) =>
        Clean(declared).ShouldBe(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("NOASSERTION")]
    [InlineData("OTHER")]
    [InlineData("LicenseRef-scancode-unknown")]
    [InlineData("LicenseRef-scancode-ms-asp-net-software AND OTHER")]
    public void Clean_SentinelOrEmpty_IsDropped(string? declared) =>
        Clean(declared).ShouldBeNull();
}
