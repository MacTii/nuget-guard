using System.Net;
using System.Text;
using NuGetGuard.Models;
using NuGetGuard.Services;

namespace NuGetGuard.Reporting;

public static class HtmlExporter
{
    public static string Export(ScanReport report, string outputFile)
    {
        var htmlPath = $"{outputFile}.html";
        var generatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm");

        var flat = report.Vulnerable.Concat(report.Deprecated).Concat(report.Outdated).ToList();
        var redundantRows = BuildRedundantRows(report);
        var unusedRows = BuildUnusedRows(report);
        var allResults = Rankings.ForReport(flat).ToList();

        // Rowspan grouping per Category|Package
        var groupCounts = new Dictionary<string, int>();
        foreach (var row in allResults)
        {
            var key = $"{row.Category}|{row.Package}";
            groupCounts[key] = groupCounts.GetValueOrDefault(key) + 1;
        }

        var seenGroups = new HashSet<string>();
        var rows = new StringBuilder();
        foreach (var row in allResults)
        {
            var badgeColor = CategoryColor(row.Category);
            var severityColor = SeverityColor(row.Severity);
            var groupKey = $"{row.Category}|{row.Package}";

            string badgeCell = "", packageCell = "", rowClass = "group-cont";
            if (seenGroups.Add(groupKey))
            {
                var rowspan = groupCounts[groupKey];
                badgeCell = $"<td rowspan='{rowspan}' class='pkg-cell'><span class='badge' style='background:{badgeColor}'>{row.Category}</span></td>";
                packageCell = $"<td rowspan='{rowspan}' class='pkg-cell'><strong>{Encode(row.Package)}</strong></td>";
                rowClass = "group-start";
            }

            rows.AppendLine($"""
                <tr class='{rowClass}'>
                {badgeCell}
                {packageCell}
                <td><code>{Encode(row.Version)}</code></td>
                <td style='color:{severityColor};font-weight:600'>{Encode(row.Severity ?? "—")}</td>
                <td>{LinkCell(row.Advisory)}</td>
                <td>{TextCell(row.Message)}</td>
                <td>{TextCell(row.Alternative)}</td>
                <td class='projects'>{Encode(row.ProjectsDisplay)}</td>
                </tr>
                """);
        }

        var licenseRows = new StringBuilder();
        foreach (var license in report.Licenses
                     .OrderBy(l => (int)l.Risk)
                     .ThenBy(l => l.Package, StringComparer.OrdinalIgnoreCase))
        {
            var riskColor = RiskColor(license.Risk);
            var urlCell = string.IsNullOrEmpty(license.LicenseUrl)
                ? "—"
                : $"<a href='{WebUtility.HtmlEncode(license.LicenseUrl)}' target='_blank'>🔗</a>";

            licenseRows.AppendLine($"""
                <tr>
                <td><strong>{Encode(license.Package)}</strong></td>
                <td><code>{Encode(license.Version)}</code></td>
                <td>{LicenseBadges(license.License)}</td>
                <td style='color:{riskColor};font-weight:600'>{license.Risk}</td>
                <td>{urlCell}</td>
                <td class='projects'>{Encode(license.Projects)}</td>
                </tr>
                """);
        }

        var outdatedNote = report.OutdatedScanFailed
            ? "<div class='build-error'>⚠️ Outdated scan incomplete — fix build errors and re-run.</div>"
            : "";
        var outdatedNum = report.OutdatedScanFailed ? "?" : report.Outdated.Count.ToString();

        var html = $$"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <title>NuGet Package Report</title>
            <style>
            *{box-sizing:border-box;margin:0;padding:0}
            body{font-family:Segoe UI,sans-serif;background:#f0f2f5;padding:2rem;color:#333}
            h1{font-size:1.7rem;margin-bottom:.25rem}
            h2{font-size:1.2rem;margin:2rem 0 .75rem;color:#2c3e50}
            .sub{color:#888;margin-bottom:1.5rem}
            .summary{display:flex;gap:1.25rem;flex-wrap:wrap;margin-bottom:1.75rem}
            .group{background:#fff;border-radius:12px;padding:.9rem 1.1rem 1rem;box-shadow:0 1px 4px rgba(0,0,0,.08);flex:1;min-width:280px}
            .group-lbl{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;color:#95a5a6;font-weight:700;margin-bottom:.7rem}
            .cards{display:flex;gap:.5rem}
            .card{flex:1;text-align:center;padding:.2rem}
            .num{font-size:1.9rem;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1}
            .lbl{font-size:.72rem;color:#888;margin-top:.2rem}
            .build-error{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:.75rem 1rem;margin-bottom:1rem;color:#7a5f00;font-size:.88rem}
            table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:2rem}
            th{background:#2c3e50;color:#fff;padding:.75rem 1rem;text-align:left;font-size:.8rem;text-transform:uppercase}
            td{padding:.65rem 1rem;border-bottom:1px solid #f0f0f0;font-size:.88rem;vertical-align:top}
            tr:hover td:not(.pkg-cell){background:#fafafa}
            .group-start td{border-top:2px solid #d0d7de}
            .pkg-cell{background:#fafbfc;border-right:1px solid #eaecef}
            .badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;color:#fff;font-size:.72rem;font-weight:600}
            .lic-badge{display:inline-block;padding:.2rem .65rem;border-radius:20px;color:#fff;font-size:.78rem;font-weight:600}
            .lic-badges{display:inline-flex;flex-wrap:wrap;gap:.3rem;vertical-align:middle}
            .projects{color:#999;font-size:.78rem}
            code{background:#f4f4f4;padding:.1rem .4rem;border-radius:4px}
            a{text-decoration:none;color:#3498db}
            </style>
            </head>
            <body>

            <h1>📦 NuGet Package Report</h1>
            <p class="sub">Solution: <strong>{{Encode(report.SolutionName)}}</strong> &nbsp;|&nbsp; Generated: {{generatedAt}}</p>

            <div class="summary">
            <div class="group">
            <div class="group-lbl">🚨 Issues</div>
            <div class="cards">
            <div class="card"><div class="num" style="color:#e74c3c">{{report.Vulnerable.Count}}</div><div class="lbl">Vulnerable</div></div>
            <div class="card"><div class="num" style="color:#e67e22">{{report.Deprecated.Count}}</div><div class="lbl">Deprecated</div></div>
            <div class="card"><div class="num" style="color:#3498db">{{outdatedNum}}</div><div class="lbl">Outdated</div></div>
            </div>
            </div>
            <div class="group">
            <div class="group-lbl">📜 Licenses</div>
            <div class="cards">
            <div class="card"><div class="num" style="color:#e74c3c">{{report.StrongCopyleftCount}}</div><div class="lbl">Strong Copyleft</div></div>
            <div class="card"><div class="num" style="color:#8e44ad">{{report.ProprietaryLicenseCount}}</div><div class="lbl">Proprietary</div></div>
            <div class="card"><div class="num" style="color:#aaa">{{report.UnknownLicenseCount}}</div><div class="lbl">Unknown</div></div>
            </div>
            </div>
            <div class="group">
            <div class="group-lbl">🧹 Hygiene</div>
            <div class="cards">
            <div class="card"><div class="num" style="color:#9b59b6">{{report.RedundantCount}}</div><div class="lbl">Redundant</div></div>
            <div class="card"><div class="num" style="color:#16a085">{{report.UnusedCount}}</div><div class="lbl">Possibly Unused</div></div>
            </div>
            </div>
            </div>

            {{outdatedNote}}

            <h2>🚨 Issues</h2>
            <table>
            <thead>
            <tr><th>Category</th><th>Package</th><th>Version</th><th>Severity</th><th>Advisory</th><th>Message</th><th>Alternative</th><th>Projects</th></tr>
            </thead>
            <tbody>
            {{rows}}
            </tbody>
            </table>

            <h2>📜 License Audit</h2>
            <table>
            <thead>
            <tr><th>Package</th><th>Version</th><th>License</th><th>Risk</th><th>URL</th><th>Projects</th></tr>
            </thead>
            <tbody>
            {{licenseRows}}
            </tbody>
            </table>

            {{redundantRows}}

            {{unusedRows}}

            </body>
            </html>
            """;

        File.WriteAllText(htmlPath, html, Encoding.UTF8);
        return htmlPath;
    }

    private static string BuildRedundantRows(ScanReport report)
    {
        if (report.Redundant.Count == 0)
            return "";

        var rows = new StringBuilder();
        foreach (var group in report.Redundant)
        {
            var projectLabel = group.IsLegacy ? $"{group.ProjectName} (legacy)" : group.ProjectName;

            foreach (var item in group.Items)
            {
                var note = string.IsNullOrEmpty(item.CoveredBySource)
                    ? "—"
                    : item.CoveredBySource.StartsWith('⚠')
                        ? $"<span style='color:#e67e22;font-weight:600'>{Encode(item.CoveredBySource)}</span>"
                        : $"<span class='projects'>{Encode(item.CoveredBySource)}</span>";

                rows.AppendLine($"""
                    <tr>
                    <td class='projects'>{Encode(projectLabel)}</td>
                    <td><strong>{Encode(item.Package)}</strong></td>
                    <td><code>{Encode(item.Version)}</code></td>
                    <td>{Encode(item.CoveredBy)} <code>{Encode(item.CoveredByVersion)}</code></td>
                    <td>{note}</td>
                    </tr>
                    """);
            }
        }

        return $"""
            <h2>🔗 Redundant Packages</h2>
            <div class='build-error'>ℹ️ These direct references are already pulled in transitively by another package or a referenced project. In <code>packages.config</code> projects the full closure is listed by design, so entries there are informational only.</div>
            <table>
            <thead>
            <tr><th>Project</th><th>Package</th><th>Version</th><th>Already pulled in by</th><th>Note</th></tr>
            </thead>
            <tbody>
            {rows}
            </tbody>
            </table>
            """;
    }

    private static string BuildUnusedRows(ScanReport report)
    {
        if (report.Unused.Count == 0)
            return "";

        var rows = new StringBuilder();
        foreach (var group in report.Unused)
        {
            foreach (var item in group.Items)
            {
                rows.AppendLine($"""
                    <tr>
                    <td class='projects'>{Encode(group.ProjectName)}</td>
                    <td><strong>{Encode(item.Package)}</strong></td>
                    <td><code>{Encode(item.Version)}</code></td>
                    <td class='projects'>{Encode(item.Namespaces)}</td>
                    </tr>
                    """);
            }
        }

        return $"""
            <h2>🧹 Possibly Unused Packages</h2>
            <div class='build-error'>⚠️ Heuristic — packages used only via configuration, dependency injection or reflection also appear here. Review before removing.</div>
            <table>
            <thead>
            <tr><th>Project</th><th>Package</th><th>Version</th><th>Namespaces not referenced</th></tr>
            </thead>
            <tbody>
            {rows}
            </tbody>
            </table>
            """;
    }

    private static string Encode(string? value) => WebUtility.HtmlEncode(value ?? "");

    private static string TextCell(string? value) =>
        string.IsNullOrEmpty(value) ? "—" : Encode(value);

    private static string LinkCell(string? url) =>
        string.IsNullOrEmpty(url) ? "—" : $"<a href='{WebUtility.HtmlEncode(url)}' target='_blank'>Open</a>";

    private static string CategoryColor(string category) => category switch
    {
        "Vulnerable" => "#e74c3c",
        "Deprecated" => "#e67e22",
        "Outdated" => "#3498db",
        _ => "#555",
    };

    private static string SeverityColor(string? severity) => Rankings.SeverityOrder(severity) switch
    {
        0 => "#e74c3c",
        1 => "#c0392b",
        2 => "#e67e22",
        _ => "#555",
    };

    private static string RiskColor(LicenseRisk risk) => risk switch
    {
        LicenseRisk.Permissive => "#27ae60",
        LicenseRisk.WeakCopyleft => "#e67e22",
        LicenseRisk.StrongCopyleft => "#e74c3c",
        LicenseRisk.Proprietary => "#8e44ad",
        _ => "#aaa",
    };

    /// <summary>
    /// One badge per licence, each coloured by its own risk. A compound expression
    /// ("A OR B") becomes several badges sitting side by side, so a tri-licensed package
    /// shows its red and yellow options at a glance instead of one long label.
    /// </summary>
    private static string LicenseBadges(string license)
    {
        foreach (var op in new[] { " OR ", " AND " })
        {
            if (!license.Contains(op, StringComparison.OrdinalIgnoreCase))
                continue;

            var badges = license
                .Split(op, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(term => Badge(term.Trim('(', ')', ' ')));
            return $"<span class='lic-badges'>{string.Concat(badges)}</span>";
        }

        return Badge(license);
    }

    private static string Badge(string license) =>
        $"<span class='lic-badge' style='background:{RiskColor(LicenseCatalog.GetRisk(license))}'>{Encode(license)}</span>";
}
