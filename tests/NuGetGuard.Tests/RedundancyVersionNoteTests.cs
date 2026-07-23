using System.Reflection;
using NuGet.Versioning;
using NuGetGuard.Services;

namespace NuGetGuard.Tests;

/// <summary>Covers the version-comparison helpers behind the redundant check's ⚠ note.</summary>
public class RedundancyVersionNoteTests
{
    private static NuGetVersion? ParseFloor(string? range) => Invoke<NuGetVersion?>("ParseFloor", range);

    private static string VersionNote(string pinned, NuGetVersion? floor) =>
        Invoke<string>("VersionNote", pinned, floor)!;

    private static T? Invoke<T>(string name, params object?[] args)
    {
        var method = typeof(RedundancyAnalyzer)
            .GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!;
        return (T?)method.Invoke(null, args);
    }

    [Theory]
    [InlineData("[5.0.4, )", "5.0.4")]
    [InlineData("5.0.4", "5.0.4")]        // bare version means ">= 5.0.4"
    [InlineData("[1.0.0, 2.0.0)", "1.0.0")]
    public void ParseFloor_ExtractsLowerBound(string range, string expected) =>
        ParseFloor(range)!.ToString().ShouldBe(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-range!!")]
    public void ParseFloor_Unparseable_IsNull(string? range) =>
        ParseFloor(range).ShouldBeNull();

    [Fact]
    public void VersionNote_SameVersion_IsBlank() =>
        VersionNote("13.0.2", NuGetVersion.Parse("13.0.2")).ShouldBe("");

    [Fact]
    public void VersionNote_PinnedAboveFloor_Warns() =>
        VersionNote("13.0.2", NuGetVersion.Parse("5.0.4"))
            .ShouldBe("⚠ version differs — transitive brings 5.0.4");

    [Fact]
    public void VersionNote_PinnedBelowFloor_Warns() =>
        VersionNote("4.9.1", NuGetVersion.Parse("6.0.0"))
            .ShouldBe("⚠ version differs — transitive brings 6.0.0");

    [Fact]
    public void VersionNote_NoFloorOrUnparseablePin_IsBlank()
    {
        VersionNote("13.0.2", null).ShouldBe("");
        VersionNote("not-a-version", NuGetVersion.Parse("5.0.4")).ShouldBe("");
    }
}
