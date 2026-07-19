using System.Text;
using NuGetGuard.Commands;
using Spectre.Console.Cli;

Console.OutputEncoding = Encoding.UTF8;

var app = new CommandApp<ScanCommand>();
app.Configure(config =>
{
    config.SetApplicationName("nuget-guard");
    config.AddCommand<ScanCommand>("scan")
        .WithDescription("Audits NuGet packages: vulnerabilities, deprecations, outdated versions, license risk and redundant references.")
        .WithExample("scan")
        .WithExample("scan", "C:/Projects/MyApp", "--export", "html")
        .WithExample("scan", "--export", "csv", "--output", "reports/my-project")
        .WithExample("scan", "--fail-on", "vulnerable");
});

return await app.RunAsync(args);
