using System.Text.RegularExpressions;

namespace NuGetGuard.Services;

/// <summary>
/// Identifies a licence from its text. Shared by the licence-page fetcher and the reader of
/// licence files shipped inside packages.
/// </summary>
public static class SpdxTextMatcher
{
    /// <summary>
    /// Fingerprints ordered most specific first: the Affero preamble has to win over the plain GPL
    /// one, and "Apache License, Version 2.0" over a bare mention of Apache.
    /// </summary>
    private static readonly (string Spdx, string Pattern)[] Patterns =
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

    /// <summary>The SPDX id the text matches, or null when nothing does.</summary>
    public static string? Identify(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        foreach (var (spdx, pattern) in Patterns)
        {
            if (Regex.IsMatch(text, pattern,
                    RegexOptions.IgnoreCase | RegexOptions.Singleline,
                    TimeSpan.FromSeconds(2)))
                return spdx;
        }

        return null;
    }
}
