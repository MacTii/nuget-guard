namespace NuGetGuard.Services.DotNet;

internal sealed record ProcessResult(string Stdout, string Stderr, int ExitCode);
