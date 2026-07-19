namespace NuGetGuard.Services.DotNet;

public sealed record DotnetJsonResult(DotnetListReport? Report, bool HasError);
