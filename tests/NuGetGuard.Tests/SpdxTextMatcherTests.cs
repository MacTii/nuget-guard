using NuGetGuard.Services;

namespace NuGetGuard.Tests;

public class SpdxTextMatcherTests
{
    [Theory]
    [InlineData("MIT License\n\nPermission is hereby granted, free of charge", "MIT")]
    [InlineData("Apache License\nVersion 2.0, January 2004", "Apache-2.0")]
    [InlineData("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007", "LGPL-3.0")]
    [InlineData("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3", "AGPL-3.0")]
    public void Identify_OpenSourceText_IsRecognised(string text, string expected) =>
        SpdxTextMatcher.Identify(text).ShouldBe(expected);

    [Fact]
    public void Identify_DualLicenseAgreement_IsCommercial() =>
        SpdxTextMatcher.Identify("EFCore.BulkExtensions DUAL LICENSE AGREEMENT\nVersion 1.0, January 2023")
            .ShouldBe("Commercial");

    [Fact]
    public void Identify_OracleFreeTerms_IsOracleFutc() =>
        SpdxTextMatcher.Identify("Oracle Free Distribution, Hosting, and Use Terms and Conditions")
            .ShouldBe("Oracle-FUTC");

    [Fact]
    public void Identify_MicrosoftEula_IsMsEula() =>
        SpdxTextMatcher.Identify("MICROSOFT SOFTWARE LICENSE TERMS\nMICROSOFT .NET LIBRARY")
            .ShouldBe("MS-EULA");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("All rights reserved. Contact sales for terms.")]
    public void Identify_Unrecognisable_IsNull(string? text) =>
        SpdxTextMatcher.Identify(text).ShouldBeNull();
}
