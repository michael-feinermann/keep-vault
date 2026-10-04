namespace KalynaArchiver.Services;

/// <summary>The one import contract for key-sheet factors, never for password or PIN.</summary>
public static class FactorInput
{
    public const int HexLength = 256;
    public const int ByteLength = 128;
    public const int MaxRawCodeUnits = 65_536;

    public enum Error { None, RawTextTooLong, ForbiddenCharacter, TooManyHexCharacters, Incomplete, TransferFailed, StaleTransfer }

    // The char.IsWhiteSpace set for the pinned .NET runtime. Tests enumerate the
    // entire UTF-16 range to detect runtime drift rather than silently broadening it.
    public static bool IsFormattingWhiteSpace(char c) => c is
        >= '\u0009' and <= '\u000D' or '\u0020' or '\u0085' or '\u00A0' or '\u1680'
        or >= '\u2000' and <= '\u200A' or '\u2028' or '\u2029' or '\u202F' or '\u205F' or '\u3000';

    public static bool IsAsciiHex(char c) => c is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f';

    public static Error Validate(ReadOnlySpan<char> raw, bool requireComplete, out int hexCount)
    {
        hexCount = 0;
        if (raw.Length > MaxRawCodeUnits) return Error.RawTextTooLong;
        Error error = Count(raw, ref hexCount);
        if (error != Error.None) return error;
        return requireComplete && hexCount != HexLength ? Error.Incomplete : Error.None;
    }

    /// <summary>Validates the complete replacement before allocating its combined text.</summary>
    public static Error ValidateReplacement(string current, int start, int end, string insertion, out int hexCount)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(insertion);
        if (start < 0 || end < start || end > current.Length) throw new ArgumentOutOfRangeException(nameof(start));
        hexCount = 0;
        long length = (long)current.Length - (end - start) + insertion.Length;
        if (length > MaxRawCodeUnits) return Error.RawTextTooLong;
        Error error = Count(current.AsSpan(0, start), ref hexCount);
        if (error == Error.None) error = Count(insertion.AsSpan(), ref hexCount);
        if (error == Error.None) error = Count(current.AsSpan(end), ref hexCount);
        return error;
    }

    private static Error Count(ReadOnlySpan<char> raw, ref int hexCount)
    {
        foreach (char c in raw)
        {
            if (IsFormattingWhiteSpace(c)) continue;
            if (!IsAsciiHex(c)) return Error.ForbiddenCharacter;
            if (++hexCount > HexLength) return Error.TooManyHexCharacters;
        }
        return Error.None;
    }

    public static void RequireComplete(ReadOnlySpan<char> raw)
    {
        Error error = Validate(raw, requireComplete: true, out _);
        if (error != Error.None)
            throw new ArgumentException(Message(error, "en"));
    }

    public static string Canonicalize(string raw)
    {
        ArgumentNullException.ThrowIfNull(raw);
        RequireComplete(raw.AsSpan());
        return string.Create(HexLength, raw, static (target, source) =>
        {
            int output = 0;
            foreach (char c in source)
            {
                if (IsFormattingWhiteSpace(c)) continue;
                target[output++] = c is >= 'a' and <= 'f' ? (char)(c - ('a' - 'A')) : c;
            }
        });
    }

    /// <summary>Validates all input before touching the caller's existing sensitive buffer.</summary>
    public static void Decode(ReadOnlySpan<char> raw, Span<byte> target)
    {
        if (target.Length != ByteLength) throw new ArgumentException("The factor buffer must contain exactly 128 bytes.", nameof(target));
        RequireComplete(raw);
        int high = -1, output = 0;
        foreach (char c in raw)
        {
            if (IsFormattingWhiteSpace(c)) continue;
            int nibble = c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
            if (high < 0) high = nibble;
            else { target[output++] = (byte)((high << 4) | nibble); high = -1; }
        }
    }

    public static string Message(Error error, string? language) => (language == "en", error) switch
    {
        (_, Error.None) => string.Empty,
        (true, Error.RawTextTooLong) => "The complete insertion was rejected: a factor may contain at most 65,536 UTF-16 characters including formatting whitespace.",
        (false, Error.RawTextTooLong) => "Die gesamte Einfügung wurde abgelehnt: Ein Faktor darf einschließlich Formatierungsleerraum höchstens 65.536 UTF-16-Zeichen enthalten.",
        (true, Error.ForbiddenCharacter) => "The complete insertion was rejected: only ASCII hexadecimal characters and supported formatting whitespace are allowed.",
        (false, Error.ForbiddenCharacter) => "Die gesamte Einfügung wurde abgelehnt: Nur ASCII-Hexadezimalzeichen und unterstützter Formatierungsleerraum sind erlaubt.",
        (true, Error.TooManyHexCharacters) => "The complete insertion was rejected: a factor may contain at most 256 hexadecimal characters.",
        (false, Error.TooManyHexCharacters) => "Die gesamte Einfügung wurde abgelehnt: Ein Faktor darf höchstens 256 Hexadezimalzeichen enthalten.",
        (true, Error.Incomplete) => "Each factor must contain exactly 256 ASCII hexadecimal characters after removing supported formatting whitespace.",
        (false, Error.Incomplete) => "Jeder Faktor muss nach Entfernung unterstützten Formatierungsleerraums genau 256 ASCII-Hexadezimalzeichen enthalten.",
        (true, Error.StaleTransfer) => "The field changed during the transfer. Insert the factor again.",
        (false, Error.StaleTransfer) => "Das Feld wurde während der Übertragung geändert. Füge den Faktor erneut ein.",
        (true, _) => "The factor could not be imported. The previous text was retained.",
        (false, _) => "Der Faktor konnte nicht importiert werden. Der bisherige Text wurde erhalten.",
    };
}
