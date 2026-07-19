namespace NuGetGuard.Commands;

/// <summary>Which finding category should produce a non-zero exit code (CI gate).</summary>
public enum FailOn { None, Vulnerable, Deprecated, Outdated, StrongCopyleft, Any }
