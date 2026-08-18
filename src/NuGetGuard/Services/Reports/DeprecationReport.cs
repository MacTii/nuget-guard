using NuGetGuard.Models;

namespace NuGetGuard.Services.Reports;

/// <summary>Deprecated packages and the replacement their author recommends.</summary>
public static class DeprecationReport
{
    public static List<ReportItem> Build(IReadOnlyList<PackageMetadata> metadata)
    {
        var items = new List<ReportItem>();
        foreach (var meta in metadata.Where(m => m.IsDeprecated))
        {
            var item = new ReportItem
            {
                Category = "Deprecated",
                Package = meta.Id,
                Version = meta.Version,
                Severity = meta.DeprecationReasons,
                Message = meta.DeprecationMessage,
                Alternative = meta.AlternativeId is not null
                    ? $"{meta.AlternativeId} {meta.AlternativeRange}".Trim()
                    : null,
            };
            item.AddProjects(meta.Projects);
            items.Add(item);
        }
        return items.OrderBy(i => Rankings.SeverityOrder(i.Severity)).ToList();
    }
}
