using System.Buffers.Binary;
using System.Text;

internal static class MachOInspector
{
    private const long MaximumCommandBytes = 64 * 1024 * 1024;
    private sealed record Slice(long Offset, long Size, uint Cpu, uint Subtype);

    internal static string Inspect(string path)
    {
        using MacBoundFile file = MacBoundFile.Open(path);
        List<Slice> slices = ReadSlices(file.Stream);
        var architectures = new SortedSet<string>(StringComparer.Ordinal);
        foreach (Slice slice in slices)
        {
            string name = InspectSlice(file.Stream, slice);
            if (!architectures.Add(name)) throw new InvalidDataException("Duplicate Mach-O architecture.");
        }
        if (!architectures.Contains("arm64")) throw new InvalidDataException("The required arm64 slice is absent.");
        file.AssertStable();
        return string.Join(" ", architectures);
    }

    private static List<Slice> ReadSlices(Stream stream)
    {
        byte[] first = ReadAt(stream, 0, 8);
        uint magic = BinaryPrimitives.ReadUInt32BigEndian(first);
        bool fat64 = magic is 0xCAFEBABF or 0xBFBAFECA;
        bool fat = fat64 || magic is 0xCAFEBABE or 0xBEBAFECA;
        if (!fat) return [new(0, stream.Length, 0, 0)];
        bool little = magic is 0xBEBAFECA or 0xBFBAFECA;
        uint count = U32(first, 4, little);
        if (count is < 1 or > 16) throw new InvalidDataException("Invalid or excessive fat Mach-O architecture count.");
        int stride = fat64 ? 32 : 20;
        int tableLength = checked((int)count * stride);
        byte[] table = ReadAt(stream, 8, tableLength);
        long tableEnd = 8L + tableLength;
        var slices = new List<Slice>();
        for (int i = 0; i < count; i++)
        {
            int at = i * stride;
            ulong offset = fat64 ? U64(table, at + 8, little) : U32(table, at + 8, little);
            ulong size = fat64 ? U64(table, at + 16, little) : U32(table, at + 12, little);
            uint alignment = U32(table, at + (fat64 ? 24 : 16), little);
            if (fat64 && U32(table, at + 28, little) != 0) throw new InvalidDataException("Nonzero reserved fat-architecture field.");
            if (offset < (ulong)tableEnd || size < 32 || offset > (ulong)stream.Length
                || size > (ulong)stream.Length - offset || alignment > 31
                || (offset & ((1UL << (int)alignment) - 1)) != 0)
                throw new InvalidDataException("Invalid fat Mach-O slice bounds or alignment.");
            var slice = new Slice(checked((long)offset), checked((long)size), U32(table, at, little), U32(table, at + 4, little));
            if (slices.Any(other => slice.Offset < other.Offset + other.Size && other.Offset < slice.Offset + slice.Size))
                throw new InvalidDataException("Overlapping Mach-O slices.");
            slices.Add(slice);
        }
        return slices;
    }

    private static string InspectSlice(Stream stream, Slice slice)
    {
        if (slice.Size < 32) throw new InvalidDataException("Truncated Mach-O header.");
        byte[] header = ReadAt(stream, slice.Offset, 32);
        uint magic = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (magic is not (0xFEEDFACF or 0xCFFAEDFE)) throw new InvalidDataException("A supported 64-bit Mach-O header is required.");
        bool little = magic == 0xCFFAEDFE;
        uint cpu = U32(header, 4, little);
        uint subtype = U32(header, 8, little);
        if (slice.Cpu != 0 && (cpu != slice.Cpu || subtype != slice.Subtype))
            throw new InvalidDataException("Fat table CPU fields differ from their slice header.");
        string architecture = (cpu, subtype & 0x00FFFFFF) switch
        {
            (0x0100000C, 0) => "arm64",
            (0x01000007, 3) => "x86_64",
            _ => throw new InvalidDataException("Unsupported Mach-O CPU type or subtype.")
        };
        uint fileType = U32(header, 12, little);
        if (fileType is not (2 or 6 or 8)) throw new InvalidDataException("Expected an executable, dylib or Mach-O bundle.");
        uint count = U32(header, 16, little);
        uint commandBytes = U32(header, 20, little);
        if (count > 65_536 || commandBytes > MaximumCommandBytes || commandBytes > slice.Size - 32
            || (ulong)count * 8 > commandBytes || U32(header, 28, little) != 0)
            throw new InvalidDataException("Invalid Mach-O load-command bounds.");
        byte[] commands = ReadAt(stream, slice.Offset + 32, checked((int)commandBytes));
        int offset = 0;
        for (int index = 0; index < count; index++)
        {
            if (offset > commands.Length - 8) throw new InvalidDataException("Truncated Mach-O load command.");
            uint command = U32(commands, offset, little);
            uint bytes = U32(commands, offset + 4, little);
            if (bytes < 8 || (bytes & 7) != 0 || bytes > commands.Length - offset)
                throw new InvalidDataException("Invalid Mach-O load-command length.");
            if (command is 0xC or 0x80000018 or 0x8000001F or 0x20 or 0x80000023)
            {
                if (bytes < 24) throw new InvalidDataException("Truncated Mach-O dylib command.");
                uint nameOffset = U32(commands, offset + 8, little);
                if (nameOffset < 24 || nameOffset >= bytes) throw new InvalidDataException("Invalid dependency string offset.");
                ReadOnlySpan<byte> field = commands.AsSpan(offset + (int)nameOffset, (int)(bytes - nameOffset));
                int nul = field.IndexOf((byte)0);
                if (nul <= 0) throw new InvalidDataException("Unterminated or empty Mach-O dependency.");
                string dependency = new UTF8Encoding(false, true).GetString(field[..nul]);
                if (dependency.Any(char.IsControl)
                    || dependency.Split('/').Any(component => component is "." or "..")
                    || !(dependency.StartsWith("/System/Library/", StringComparison.Ordinal)
                        || dependency.StartsWith("/usr/lib/", StringComparison.Ordinal)
                        || dependency.StartsWith("@rpath/", StringComparison.Ordinal)
                        || dependency.StartsWith("@loader_path/", StringComparison.Ordinal)
                        || dependency.StartsWith("@executable_path/", StringComparison.Ordinal)))
                    throw new InvalidDataException("Non-system Mach-O dependency is blocked: " + dependency);
            }
            // LC_ID_DYLIB is an install name, not a load-time dependency.
            offset = checked(offset + (int)bytes);
        }
        if (offset != commands.Length) throw new InvalidDataException("Mach-O load-command count does not cover its declared table.");
        return architecture;
    }

    private static byte[] ReadAt(Stream stream, long offset, int count)
    {
        if (offset < 0 || count < 0 || offset > stream.Length || count > stream.Length - offset)
            throw new InvalidDataException("Truncated Mach-O data.");
        stream.Position = offset;
        byte[] bytes = new byte[count];
        stream.ReadExactly(bytes);
        return bytes;
    }
    private static uint U32(ReadOnlySpan<byte> bytes, int offset, bool little) => little
        ? BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]) : BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]);
    private static ulong U64(ReadOnlySpan<byte> bytes, int offset, bool little) => little
        ? BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]) : BinaryPrimitives.ReadUInt64BigEndian(bytes[offset..]);
}
