using System.Net;

namespace NuGetGuard.Services;

/// <summary>Single shared HttpClient for the whole tool (gzip-aware — required by the registration5-gz endpoint).</summary>
public static class SharedHttpClient
{
    public static HttpClient Instance { get; } = Create();

    private static HttpClient Create()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        };
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("NuGetGuard/1.0");
        return client;
    }
}
