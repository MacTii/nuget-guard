namespace NuGetGuard.Services.Licensing;

/// <summary>Resolves an SPDX license identifier from a licenseUrl — by URL pattern first, then by fetching page content.</summary>
public sealed class LicenseUrlResolver(HttpClient http)
{
    private static readonly (string Fragment, string Spdx)[] UrlPatterns =
    [
        ("opensource.org/licenses/MIT", "MIT"),
        ("apache.org/licenses/LICENSE-2.0", "Apache-2.0"),
        ("opensource.org/licenses/Apache-2.0", "Apache-2.0"),
        ("opensource.org/licenses/apache2", "Apache-2.0"),
        ("opensource.org/licenses/BSD-2-Clause", "BSD-2-Clause"),
        ("opensource.org/licenses/BSD-3-Clause", "BSD-3-Clause"),
        ("opensource.org/licenses/ISC", "ISC"),
        ("gnu.org/licenses/gpl-2", "GPL-2.0"),
        ("gnu.org/licenses/gpl-3", "GPL-3.0"),
        ("gnu.org/licenses/lgpl-2", "LGPL-2.1"),
        ("gnu.org/licenses/lgpl-3", "LGPL-3.0"),
        ("gnu.org/licenses/agpl", "AGPL-3.0"),
        // Unversioned GNU pages point at the current version (v3). The lesser/affero
        // entries must stay above the plain gpl one so the more specific match wins.
        ("gnu.org/licenses/lgpl", "LGPL-3.0"),
        ("gnu.org/licenses/gpl", "GPL-3.0"),
        ("mozilla.org/MPL/2.0", "MPL-2.0"),
        ("mozilla.org/MPL/MPL-1.1", "MPL-1.1"),
        ("mozilla.org/MPL/1.1", "MPL-1.1"),
        ("MPL-1.1", "MPL-1.1"),
        ("opensource.org/licenses/ms-pl", "MS-PL"),
        ("unlicense.org", "Unlicense"),
        ("creativecommons.org/publicdomain/zero", "CC0-1.0"),
        ("licenses.nuget.org/MIT", "MIT"),
        ("licenses.nuget.org/Apache-2.0", "Apache-2.0"),
        ("licenses.nuget.org/BSD-2-Clause", "BSD-2-Clause"),
        ("licenses.nuget.org/BSD-3-Clause", "BSD-3-Clause"),
        ("licenses.nuget.org/ISC", "ISC"),
        ("licenses.nuget.org/GPL-2.0", "GPL-2.0"),
        ("licenses.nuget.org/GPL-3.0", "GPL-3.0"),
        ("licenses.nuget.org/LGPL-2.1", "LGPL-2.1"),
        ("licenses.nuget.org/LGPL-3.0", "LGPL-3.0"),
        ("licenses.nuget.org/AGPL-3.0", "AGPL-3.0"),
        ("licenses.nuget.org/MPL-2.0", "MPL-2.0"),
        ("licenses.nuget.org/MS-PL", "MS-PL"),
        ("licenses.nuget.org/Unlicense", "Unlicense"),
        ("licenses.nuget.org/CC0-1.0", "CC0-1.0"),
        ("github.com/dotnet", "MIT"), // most Microsoft/dotnet packages
        // Microsoft's own EULA pages. The links are long dead, so naming the licence from the URL
        // is the only way left to tell a proprietary Microsoft licence from an unchecked one.
        ("microsoft.com/web/webpi/eula/", "MS-EULA"),
        // Commercial vendors whose licence URL points at their own EULA
        ("devexpress.com", "Commercial"),
    ];

    // Ordered from most specific to least specific
    /// <summary>Fast resolution from URL pattern alone — no HTTP.</summary>
    public static string? ResolveFromUrlPattern(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return null;

        foreach (var (fragment, spdx) in UrlPatterns)
        {
            if (url.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return spdx;
        }
        return null;
    }

    /// <summary>Fetches the license page and matches SPDX identifiers in its content.</summary>
    public async Task<string?> ResolveFromContentAsync(string? url, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
            return null;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));
            var content = await http.GetStringAsync(url, cts.Token);
            return SpdxTextMatcher.Identify(content);
        }
        catch
        {
            // Network failures / timeouts are non-fatal — license simply stays unresolved.
        }

        return null;
    }
}
