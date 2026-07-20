namespace NuGetGuard.Services;

/// <summary>
/// Packages that back-port framework types to older targets. They are pulled in to satisfy
/// other packages at compile time, so they must never be reported as redundant or unused.
/// </summary>
public static class FrameworkPolyfills
{
    private static readonly HashSet<string> Ids = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Buffers", "System.Memory", "System.Numerics.Vectors",
        "System.Runtime.CompilerServices.Unsafe", "System.Threading.Tasks.Extensions",
        "System.ValueTuple", "System.Text.Json", "System.Text.Encodings.Web",
        "System.IO.Pipelines", "System.Threading.Channels",
        "Microsoft.Bcl.AsyncInterfaces", "System.Text.Encoding.CodePages",
    };

    public static bool Contains(string packageId) => Ids.Contains(packageId);
}
