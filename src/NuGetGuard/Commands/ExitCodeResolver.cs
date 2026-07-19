using NuGetGuard.Models;

namespace NuGetGuard.Commands;

/// <summary>Maps scan results to the process exit code according to the --fail-on setting.</summary>
public static class ExitCodeResolver
{
    public const int Success = 0;
    public const int FailOnTriggered = 1;
    public const int NoSolutionFound = 2;

    public static int Resolve(ScanReport report, FailOn failOn) => failOn switch
    {
        FailOn.Vulnerable when report.Vulnerable.Count > 0 => FailOnTriggered,
        FailOn.Deprecated when report.Deprecated.Count > 0 => FailOnTriggered,
        FailOn.Outdated when report.Outdated.Count > 0 || report.OutdatedScanFailed => FailOnTriggered,
        FailOn.StrongCopyleft when report.StrongCopyleftCount > 0 => FailOnTriggered,
        FailOn.Any when report.Vulnerable.Count > 0
                        || report.Deprecated.Count > 0
                        || report.Outdated.Count > 0
                        || report.StrongCopyleftCount > 0 => FailOnTriggered,
        _ => Success,
    };
}
