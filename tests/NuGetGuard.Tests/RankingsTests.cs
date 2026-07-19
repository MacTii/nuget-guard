using NuGetGuard.Models;

namespace NuGetGuard.Tests;

public class RankingsTests
{
    [Theory]
    [InlineData("Critical", 0)]
    [InlineData("High", 1)]
    [InlineData("Moderate", 2)]
    [InlineData("Low", 3)]
    [InlineData("critical", 0)] // case-insensitive
    [InlineData("Something else", 4)]
    [InlineData(null, 4)]
    public void SeverityOrder_RanksWorstFirst(string? severity, int expected) =>
        Rankings.SeverityOrder(severity).Should().Be(expected);

    [Theory]
    [InlineData("Vulnerable", 0)]
    [InlineData("Deprecated", 1)]
    [InlineData("Outdated", 2)]
    [InlineData("Other", 3)]
    public void CategoryOrder_RanksVulnerableFirst(string category, int expected) =>
        Rankings.CategoryOrder(category).Should().Be(expected);

    [Theory]
    [InlineData(0, "Low")]
    [InlineData(1, "Moderate")]
    [InlineData(2, "High")]
    [InlineData(3, "Critical")]
    [InlineData(99, "Unknown")]
    public void SeverityLabel_MapsRegistrationApiIntegers(int value, string expected) =>
        Rankings.SeverityLabel(value).Should().Be(expected);

    [Theory]
    [InlineData("HIGH", "High")]
    [InlineData("moderate", "Moderate")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void ToTitleCase_NormalizesSeverityCasing(string? input, string expected) =>
        Rankings.ToTitleCase(input).Should().Be(expected);

    [Fact]
    public void MaxSeverityForPackage_ReturnsWorstSeverityWithinCategoryAndPackage()
    {
        var items = new[]
        {
            NewItem("Vulnerable", "PkgA", "Moderate"),
            NewItem("Vulnerable", "PkgA", "Critical"),
            NewItem("Vulnerable", "PkgB", "Low"),
            NewItem("Deprecated", "PkgA", "High"),
        };

        Rankings.MaxSeverityForPackage(items, "Vulnerable", "PkgA").Should().Be(0);
        Rankings.MaxSeverityForPackage(items, "Vulnerable", "PkgB").Should().Be(3);
        Rankings.MaxSeverityForPackage(items, "Deprecated", "PkgA").Should().Be(1);
        Rankings.MaxSeverityForPackage(items, "Outdated", "PkgA").Should().Be(4);
    }

    private static ReportItem NewItem(string category, string package, string severity) => new()
    {
        Category = category,
        Package = package,
        Version = "1.0.0",
        Severity = severity,
    };
}
