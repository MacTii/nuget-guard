using NuGetGuard.Services.Licensing;
using NuGetGuard.Services;

namespace NuGetGuard.Tests.Licensing;

public sealed class PackageLicenseFileReaderTests : IDisposable
{
    private const string MitText = """
        MIT License

        Copyright (c) 2026 Example

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction.
        """;

    private readonly string _dir = Directory.CreateTempSubdirectory("nuget-guard-licfile").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Creates a restored package in a legacy packages folder.</summary>
    private string CreatePackage(string id, string version, Action<string> fill)
    {
        var packagesFolder = Path.Combine(_dir, "packages");
        var packageFolder = Path.Combine(packagesFolder, $"{id}.{version}");
        Directory.CreateDirectory(packageFolder);
        fill(packageFolder);
        return packagesFolder;
    }

    [Fact]
    public void Read_ConventionalLicenseFile_IsIdentified()
    {
        var packages = CreatePackage("Sample", "1.0.0", folder =>
            File.WriteAllText(Path.Combine(folder, "LICENSE.txt"), MitText));

        PackageLicenseFileReader.Read("Sample", "1.0.0", packages).ShouldBe("MIT");
    }

    [Fact]
    public void Read_FileDeclaredInNuspec_IsPreferred()
    {
        var packages = CreatePackage("Sample", "1.0.0", folder =>
        {
            File.WriteAllText(Path.Combine(folder, "Sample.nuspec"), """
                <package><metadata>
                  <id>Sample</id>
                  <license type="file">legal/COPYRIGHT.txt</license>
                </metadata></package>
                """);
            Directory.CreateDirectory(Path.Combine(folder, "legal"));
            File.WriteAllText(Path.Combine(folder, "legal", "COPYRIGHT.txt"), MitText);
        });

        PackageLicenseFileReader.Read("Sample", "1.0.0", packages).ShouldBe("MIT");
    }

    [Fact]
    public void Read_ApacheLicenseFile_IsIdentified()
    {
        var packages = CreatePackage("Sample", "1.0.0", folder =>
            File.WriteAllText(Path.Combine(folder, "LICENSE"),
                "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/"));

        PackageLicenseFileReader.Read("Sample", "1.0.0", packages).ShouldBe("Apache-2.0");
    }

    [Fact]
    public void Read_UnrecognizableText_ReturnsNull()
    {
        var packages = CreatePackage("Sample", "1.0.0", folder =>
            File.WriteAllText(Path.Combine(folder, "LICENSE.txt"), "All rights reserved. Contact sales."));

        PackageLicenseFileReader.Read("Sample", "1.0.0", packages).ShouldBeNull();
    }

    [Fact]
    public void Read_PackageWithoutLicenseFile_ReturnsNull()
    {
        var packages = CreatePackage("Sample", "1.0.0", _ => { });

        PackageLicenseFileReader.Read("Sample", "1.0.0", packages).ShouldBeNull();
    }

    [Fact]
    public void Read_PackageNotRestored_ReturnsNull() =>
        PackageLicenseFileReader.Read("Missing", "1.0.0", Path.Combine(_dir, "packages")).ShouldBeNull();
}
