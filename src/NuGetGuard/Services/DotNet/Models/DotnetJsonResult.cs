namespace NuGetGuard.Services.DotNet.Models;

public sealed record DotnetJsonResult(DotnetListReport? Report, bool HasError);
