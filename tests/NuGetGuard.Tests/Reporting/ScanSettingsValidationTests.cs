using NuGetGuard.Commands;
using Shouldly;

namespace NuGetGuard.Tests.Reporting;

public class ScanSettingsValidationTests
{
    // Failing on a check that was also switched off would always pass: the analysis never
    // runs, so it finds nothing. In CI that reads as a clean scan, which is worse than no
    // gate at all.
    [Theory]
    [InlineData(FailOn.Unused, true)]
    [InlineData(FailOn.Any, true)]
    public void Validate_FailOnACheckThatIsSkipped_IsRefused(FailOn failOn, bool skipUnused) =>
        new ScanSettings { FailOn = failOn, SkipUnused = skipUnused }
            .Validate().Successful.ShouldBeFalse();

    [Theory]
    [InlineData(FailOn.Unused, false)]
    [InlineData(FailOn.Vulnerable, true)]
    [InlineData(FailOn.None, true)]
    public void Validate_CombinationsThatCanBeHonoured_AreAccepted(FailOn failOn, bool skipUnused) =>
        new ScanSettings { FailOn = failOn, SkipUnused = skipUnused }
            .Validate().Successful.ShouldBeTrue();
}
