using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace NuGetGuard.Services.Packages;

/// <summary>
/// Reads the namespaces a package exposes, straight from assembly metadata.
/// Metadata-only — the assembly is never loaded into the process.
/// </summary>
public static class AssemblyNamespaceReader
{
    public static IReadOnlyCollection<string> ReadPublicNamespaces(string assemblyPath)
    {
        var namespaces = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var stream = File.OpenRead(assemblyPath);
            using var peReader = new PEReader(stream);

            if (!peReader.HasMetadata)
                return namespaces;

            var reader = peReader.GetMetadataReader();

            foreach (var handle in reader.TypeDefinitions)
            {
                var type = reader.GetTypeDefinition(handle);
                if ((type.Attributes & TypeAttributes.VisibilityMask) != TypeAttributes.Public)
                    continue;

                Add(namespaces, reader.GetString(type.Namespace));
            }

            // Type forwarders — facade packages expose their types this way
            foreach (var handle in reader.ExportedTypes)
            {
                var exported = reader.GetExportedType(handle);
                Add(namespaces, reader.GetString(exported.Namespace));
            }
        }
        catch (BadImageFormatException)
        {
            // native or malformed assembly — nothing to read
        }
        catch (IOException)
        {
            // unreadable file — treat as no namespaces
        }

        return namespaces;
    }

    private static void Add(HashSet<string> namespaces, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            namespaces.Add(value);
    }
}
