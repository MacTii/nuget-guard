using NuGetGuard.Checks;

namespace NuGetGuard.Tests.Checks;

public class ReportItemTests
{
    [Fact]
    public void AddProjects_DeduplicatesCaseInsensitively()
    {
        var item = new ReportItem { Category = "Vulnerable", Package = "P", Version = "1.0" };

        item.AddProjects(["App", "app", "Worker", ""]);

        item.Projects.ShouldBe(["App", "Worker"]);
        item.ProjectsDisplay.ShouldBe("App, Worker");
    }
}
