namespace NuGetGuard.Models;

/// <summary>License risk classification, ordered worst → best for sorting.</summary>
public enum LicenseRisk
{
    StrongCopyleft = 0,
    WeakCopyleft = 1,
    Unknown = 2,
    Permissive = 3,
}
