using System.Runtime.InteropServices;

namespace NuGetGuard.Services.DotNet;

/// <summary>Locates (or downloads) nuget.exe and runs legacy packages.config restores.</summary>
public static class NuGetExe
{
    public static async Task<string?> GetOrDownloadAsync(HttpClient http, CancellationToken ct = default)
    {
        var existing = FindOnPath("nuget") ?? FindOnPath("nuget.exe");
        if (existing is not null)
            return existing;

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return null;

        var cached = Path.Combine(Path.GetTempPath(), "nuget.exe");
        if (File.Exists(cached))
            return cached;

        try
        {
            var bytes = await http.GetByteArrayAsync(
                "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe", ct);
            await File.WriteAllBytesAsync(cached, bytes, ct);
            return cached;
        }
        catch
        {
            return null;
        }
    }

    public static async Task<bool> RestoreAsync(string nugetExe, string solutionPath, CancellationToken ct = default)
    {
        var result = await ProcessRunner.RunAsync(
            nugetExe,
            ["restore", solutionPath, "-NonInteractive", "-Verbosity", "quiet"],
            Path.GetDirectoryName(solutionPath)!,
            ct);
        return result.ExitCode == 0;
    }

    private static string? FindOnPath(string fileName)
    {
        var paths = (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        var extensions = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? new[] { "", ".exe", ".cmd", ".bat" }
            : [""];

        foreach (var dir in paths)
        {
            foreach (var ext in extensions)
            {
                var candidate = Path.Combine(dir, fileName + ext);
                if (File.Exists(candidate))
                    return candidate;
            }
        }
        return null;
    }
}
