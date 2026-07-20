namespace NuGetGuard.Commands;

/// <summary>
/// Which finding category should produce a non-zero exit code (CI gate).
/// <see cref="Unused"/> is opt-in only and deliberately excluded from <see cref="Any"/>,
/// because unused-package detection is heuristic.
/// </summary>
public enum FailOn { None, Vulnerable, Deprecated, Outdated, StrongCopyleft, Unused, Any }
