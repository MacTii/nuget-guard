namespace NuGetGuard.Infrastructure.DotNet;

internal sealed record ProcessResult(string Stdout, string Stderr, int ExitCode);
