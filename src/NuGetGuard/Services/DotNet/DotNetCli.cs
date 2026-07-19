using System.Text.Json;

namespace NuGetGuard.Services.DotNet;

/// <summary>Runs `dotnet list package` and parses its JSON output.</summary>
public static class DotNetCli
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public static async Task<DotnetJsonResult> ListPackagesAsync(
        string targetPath, string workingDirectory, string[] extraArgs, CancellationToken ct = default)
    {
        var args = new List<string> { "list", targetPath, "package" };
        args.AddRange(extraArgs);
        args.AddRange(["--format", "json"]);

        var result = await ProcessRunner.RunAsync("dotnet", args, workingDirectory, ct);

        // dotnet may print "error:" lines before/instead of JSON (e.g. restore failures)
        var jsonStart = result.Stdout.IndexOf('{');
        if (jsonStart < 0)
            return new DotnetJsonResult(null, HasError: true);

        try
        {
            var report = JsonSerializer.Deserialize<DotnetListReport>(result.Stdout[jsonStart..], JsonOptions);
            var hasError = result.ExitCode != 0
                || result.Stderr.Contains("error", StringComparison.OrdinalIgnoreCase)
                || result.Stdout[..jsonStart].Contains("error", StringComparison.OrdinalIgnoreCase);
            return new DotnetJsonResult(report, hasError && report is null);
        }
        catch (JsonException)
        {
            return new DotnetJsonResult(null, HasError: true);
        }
    }
}
