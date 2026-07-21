namespace NuGetGuard.Models;

/// <summary>
/// License risk classification, ordered worst → best for sorting.
///
/// <see cref="Proprietary"/> and <see cref="Unknown"/> both need a human, for opposite reasons:
/// the licence is known but not open source, or nothing could be established at all.
/// </summary>
public enum LicenseRisk
{
    StrongCopyleft = 0,
    WeakCopyleft = 1,
    Proprietary = 2,
    Unknown = 3,
    Permissive = 4,
}
