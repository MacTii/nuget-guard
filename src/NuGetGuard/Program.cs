using System.Reflection;
using System.Text;
using NuGetGuard.Commands;
using Spectre.Console.Cli;

Console.OutputEncoding = Encoding.UTF8;

// The informational version carries the source-control hash after a '+'; drop it.
var version = Assembly.GetExecutingAssembly()
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
    .InformationalVersion.Split('+')[0] ?? "unknown";

var app = new CommandApp<ScanCommand>();
app.Configure(config =>
{
    config.SetApplicationName("nuget-guard");
    config.SetApplicationVersion(version);

    // Without this a mistyped option is silently ignored and the scan runs anyway,
    // so `--fail-on-vulnerable` would leave a pipeline green while findings exist.
    config.UseStrictParsing();

    config.AddCommand<ScanCommand>("scan")
        .WithDescription("Audits NuGet packages: vulnerabilities, deprecations, outdated versions, license risk and redundant references.")
        .WithExample("scan")
        .WithExample("scan", "C:/Projects/MyApp", "--export", "html")
        .WithExample("scan", "--export", "csv", "--output", "reports/my-project")
        .WithExample("scan", "--fail-on", "vulnerable");
});

return await app.RunAsync(args);
