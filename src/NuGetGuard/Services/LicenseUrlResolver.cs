using System.Text.RegularExpressions;

namespace NuGetGuard.Services;

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
        ("mozilla.org/MPL/2.0", "MPL-2.0"),
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
    ];

    // Ordered from most specific to least specific
    private static readonly (string Spdx, string Pattern)[] ContentPatterns =
    [
        ("AGPL-3.0", @"GNU AFFERO GENERAL PUBLIC LICENSE.*Version 3|AGPL.?3\.0"),
        ("GPL-3.0", @"GNU GENERAL PUBLIC LICENSE.*Version 3(?!.*Affero)|GPL.?3\.0"),
        ("GPL-2.0", @"GNU GENERAL PUBLIC LICENSE.*Version 2(?!.*Affero)|GPL.?2\.0"),
        ("LGPL-3.0", @"GNU LESSER GENERAL PUBLIC LICENSE.*Version 3|LGPL.?3\.0"),
        ("LGPL-2.1", @"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1|LGPL.?2\.1"),
        ("LGPL-2.0", @"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2(?!\.1)|LGPL.?2\.0"),
        ("MPL-2.0", @"Mozilla Public License.*2\.0|MPL.?2\.0"),
        ("EPL-2.0", @"Eclipse Public License.*2\.0|EPL.?2\.0"),
        ("EPL-1.0", @"Eclipse Public License.*1\.0|EPL.?1\.0"),
        ("EUPL-1.2", @"European Union Public Licence.*1\.2|EUPL.?1\.2"),
        ("EUPL-1.1", @"European Union Public Licence.*1\.1|EUPL.?1\.1"),
        ("Apache-2.0", @"Apache License.*Version 2\.0|Apache.?2\.0"),
        ("BSD-3-Clause", @"BSD 3-Clause|Redistribution and use.*three.*conditions"),
        ("BSD-2-Clause", @"BSD 2-Clause|Redistribution and use.*two.*conditions"),
        ("MIT", @"Permission is hereby granted.*free of charge|MIT License"),
        ("ISC", @"ISC License|Permission to use.*copy.*modify"),
        ("MS-PL", @"Microsoft Public License|Ms-PL"),
        ("Unlicense", @"This is free and unencumbered software released into the public domain"),
        ("CC0-1.0", @"CC0 1\.0 Universal|Creative Commons.*Public Domain"),
        ("BSL-1.0", @"Boost Software License"),
    ];

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

            foreach (var (spdx, pattern) in ContentPatterns)
            {
                if (Regex.IsMatch(content, pattern,
                        RegexOptions.IgnoreCase | RegexOptions.Singleline,
                        TimeSpan.FromSeconds(2)))
                    return spdx;
            }
        }
        catch
        {
            // Network failures / timeouts are non-fatal — license simply stays unresolved.
        }

        return null;
    }
}
