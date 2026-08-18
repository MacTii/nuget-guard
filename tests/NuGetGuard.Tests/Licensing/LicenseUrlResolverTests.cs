using NuGetGuard.Services.Licensing;
using NuGetGuard.Services;

namespace NuGetGuard.Tests.Licensing;

public class LicenseUrlResolverTests
{
    [Theory]
    [InlineData("https://opensource.org/licenses/MIT", "MIT")]
    [InlineData("https://www.apache.org/licenses/LICENSE-2.0", "Apache-2.0")]
    [InlineData("https://licenses.nuget.org/Apache-2.0", "Apache-2.0")]
    [InlineData("https://licenses.nuget.org/MIT", "MIT")]
    [InlineData("https://www.gnu.org/licenses/gpl-3.0.html", "GPL-3.0")]
    [InlineData("https://www.gnu.org/licenses/lgpl-2.1.txt", "LGPL-2.1")]
    [InlineData("http://www.gnu.org/licenses/lgpl.html", "LGPL-3.0")]
    [InlineData("http://www.gnu.org/licenses/gpl.html", "GPL-3.0")]
    [InlineData("http://www.gnu.org/licenses/agpl.html", "AGPL-3.0")]
    [InlineData("http://www.mozilla.org/MPL/2.0/", "MPL-2.0")]
    [InlineData("https://github.com/dotnet/runtime/blob/main/LICENSE.TXT", "MIT")]
    [InlineData("https://www.devexpress.com/Support/EULAs", "Commercial")]
    public void ResolveFromUrlPattern_KnownHosts_ReturnSpdx(string url, string expected) =>
        LicenseUrlResolver.ResolveFromUrlPattern(url).ShouldBe(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://example.com/eula")]
    public void ResolveFromUrlPattern_UnknownUrls_ReturnNull(string? url) =>
        LicenseUrlResolver.ResolveFromUrlPattern(url).ShouldBeNull();
}
