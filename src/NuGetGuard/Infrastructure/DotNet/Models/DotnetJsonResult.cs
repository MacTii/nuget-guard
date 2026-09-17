namespace NuGetGuard.Infrastructure.DotNet.Models;

public sealed record DotnetJsonResult(DotnetListReport? Report, bool HasError);
