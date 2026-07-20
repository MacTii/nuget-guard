namespace NuGetGuard.Models;

/// <summary>Ordering and formatting helpers shared by reporting and exporters.</summary>
public static class Rankings
{
    public static int SeverityOrder(string? severity) => severity switch
    {
        null => 4,
        _ when severity.Contains("Critical", StringComparison.OrdinalIgnoreCase) => 0,
        _ when severity.Contains("High", StringComparison.OrdinalIgnoreCase) => 1,
        _ when severity.Contains("Moderate", StringComparison.OrdinalIgnoreCase) => 2,
        _ when severity.Contains("Low", StringComparison.OrdinalIgnoreCase) => 3,
        _ => 4,
    };

    public static int CategoryOrder(string category) => category switch
    {
        "Vulnerable" => 0,
        "Deprecated" => 1,
        "Outdated" => 2,
        "Unused" => 3,
        _ => 4,
    };

    public static string SeverityLabel(int value) => value switch
    {
        0 => "Low",
        1 => "Moderate",
        2 => "High",
        3 => "Critical",
        _ => "Unknown",
    };

    public static string ToTitleCase(string? value) =>
        string.IsNullOrEmpty(value)
            ? string.Empty
            : System.Globalization.CultureInfo.InvariantCulture.TextInfo.ToTitleCase(value.ToLowerInvariant());

    /// <summary>Worst (lowest) severity order among all rows for the same category + package.</summary>
    public static int MaxSeverityForPackage(IEnumerable<ReportItem> results, string category, string package)
    {
        var orders = results
            .Where(r => r.Category == category && string.Equals(r.Package, package, StringComparison.OrdinalIgnoreCase))
            .Select(r => SeverityOrder(r.Severity))
            .ToList();
        return orders.Count == 0 ? 4 : orders.Min();
    }
}
