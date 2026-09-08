using System.Globalization;

namespace KalynaArchiver.Services;

internal static partial class ContainerKeyDerivation
{
    // Bounds temporary UTF-8/ASCII and length-prefixed KDF allocations. This
    // technical ceiling is independent of the rules for choosing new secrets.
    public const int MaxCredentialCodeUnits = 1_048_576;

    public static void ValidatePasswordEncoding(string? password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length > MaxCredentialCodeUnits)
        {
            throw new ArgumentException("The password exceeds the technical input limit.", nameof(password));
        }
    }

    public static void ValidatePinEncoding(string? pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        if (pin.Length > MaxCredentialCodeUnits)
        {
            throw new ArgumentException("The PIN exceeds the technical input limit.", nameof(pin));
        }

        foreach (char digit in pin)
        {
            if (digit is < '0' or > '9')
            {
                throw new ArgumentException("The PIN must consist of ASCII digits only.", nameof(pin));
            }
        }
    }

    /// <summary>
    /// A PIN-only preview. It never confirms the password/PIN pair. Final
    /// archive creation must use the overload that also receives the raw password.
    /// </summary>
    public static PinPolicyAnalysis AnalyzePinForCreation(string? pin) =>
        AnalyzePinForCreationCore(pin, null, LocalCreationDate(), checkPair: false);

    public static PinPolicyAnalysis AnalyzePinForCreation(
        string? pin, string? rawPassword, DateOnly? localDate = null) =>
        AnalyzePinForCreationCore(pin, rawPassword, localDate ?? LocalCreationDate(), checkPair: true);

    public static void ValidatePinForCreation(
        string? pin, string? rawPassword, DateOnly? localDate = null)
    {
        PinPolicyAnalysis analysis = AnalyzePinForCreation(pin, rawPassword, localDate);
        if (!analysis.IsAccepted)
        {
            throw new PinPolicyException(analysis);
        }
    }

    internal static DateOnly LocalCreationDate(TimeProvider? clock = null) =>
        DateOnly.FromDateTime((clock ?? TimeProvider.System).GetLocalNow().DateTime);

    private static PinPolicyAnalysis AnalyzePinForCreationCore(
        string? pin, string? rawPassword, DateOnly localDate, bool checkPair)
    {
        PinPolicyAnalysis baseline = AnalyzePinBaselineForCreation(pin);
        var violations = new List<PinPolicyViolation>(baseline.Violations);
        bool passwordPresent = !string.IsNullOrEmpty(rawPassword);
        bool pairComplete = checkPair && passwordPresent
            && baseline.Length is >= MinPinLength and <= MaxPinCreationLength
            && !baseline.Violations.Contains(PinPolicyViolation.NonDigit);
        if (checkPair && !passwordPresent)
        {
            violations.Add(PinPolicyViolation.PasswordRequiredForPairCheck);
        }

        PinPattern patterns = PinPattern.None;
        if (pin is { Length: >= MinPinLength and <= MaxPinCreationLength }
            && !baseline.Violations.Contains(PinPolicyViolation.NonDigit))
        {
            if (pairComplete && rawPassword!.Contains(pin, StringComparison.Ordinal))
            {
                violations.Add(PinPolicyViolation.ContainedInPassword);
            }

            if (PinCreationPatterns.IsCurrentDate(pin, localDate))
            {
                violations.Add(PinPolicyViolation.CurrentDate);
            }

            if (PinCreationPatterns.IsPlausibleDate(pin.AsSpan()))
            {
                violations.Add(PinPolicyViolation.PlausibleDate);
            }

            patterns = PinCreationPatterns.Analyze(pin.AsSpan());
            if (patterns != PinPattern.None)
            {
                violations.Add(PinPolicyViolation.PredictablePattern);
            }
        }

        return new PinPolicyAnalysis(baseline.Length, baseline.DistinctDigits, violations)
        {
            PairCheckComplete = pairComplete,
            Patterns = patterns,
        };
    }
}

[Flags]
public enum PinPattern
{
    None = 0,
    CyclicSequence = 1,
    LongRepeatedBlock = 2,
    AlmostRepeatedBlock = 4,
    Palindrome = 8,
    YearCombination = 16,
    DateYearCombination = 32,
    KnownConstant = 64,
    StructuredKeypadWalk = 128,
}

/// <summary>
/// Versioned, offline recognition of complete simple PIN constructions.
/// These are additional selection rules, not empirical guess ranks or a claim
/// that an unrecognized human-selected PIN has a particular entropy.
/// </summary>
internal static class PinCreationPatterns
{
    internal const string ModelVersion = "keep-vault-pin-patterns-2026-09-v1";
    internal const int ReferenceYear = 2026;
    internal const int FirstPlausibleYear = 1900;
    internal const int LastPlausibleYear = ReferenceYear + 30;

    // The first sixteen decimal digits including the integer part. Only a
    // complete PIN that is a prefix is recognized, never an interior segment.
    private static readonly string[] KnownConstantPrefixes =
    [
        "3141592653589793", // pi
        "2718281828459045", // e
        "1618033988749894", // golden ratio
        "1414213562373095", // sqrt(2)
    ];

    internal static bool IsCurrentDate(string pin, DateOnly localDate)
    {
        // Exactly four full-value formats. Ordinal equality preserves leading
        // zeros and is independent of the current culture/calendar settings.
        foreach (string format in new[] { "ddMMyy", "ddMMyyyy", "MMddyy", "MMddyyyy" })
        {
            if (string.Equals(pin, localDate.ToString(format, CultureInfo.InvariantCulture), StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    internal static bool IsPlausibleDate(ReadOnlySpan<char> pin)
    {
        if (pin.Length is not (6 or 8) || !ContainsOnlyDigits(pin))
        {
            return false;
        }

        int longYearDigits = pin.Length - 4;
        return IsCalendarDate(Number(pin[..2]), Number(pin.Slice(2, 2)), Number(pin[4..]), longYearDigits)
            || IsCalendarDate(Number(pin.Slice(2, 2)), Number(pin[..2]), Number(pin[4..]), longYearDigits)
            || IsCalendarDate(Number(pin[^2..]), Number(pin.Slice(longYearDigits, 2)), Number(pin[..longYearDigits]), longYearDigits);
    }

    private static bool IsCalendarDate(int day, int month, int year, int yearDigits)
    {
        if (yearDigits == 2)
        {
            // Explicitly check both centuries, without the OS calendar's
            // changing two-digit-year cutoff. The model bounds still apply.
            return IsCalendarDate(day, month, 1900 + year, 4)
                || IsCalendarDate(day, month, 2000 + year, 4);
        }
        return year is >= FirstPlausibleYear and <= LastPlausibleYear
            && month is >= 1 and <= 12
            && day >= 1 && day <= DateTime.DaysInMonth(year, month);
    }

    internal static PinPattern Analyze(ReadOnlySpan<char> pin)
    {
        if (pin.Length is < 6 or > 16 || !ContainsOnlyDigits(pin))
        {
            return PinPattern.None;
        }

        PinPattern patterns = PinPattern.None;
        int step = (pin[1] - pin[0] + 10) % 10;
        bool cyclic = step != 0;
        for (int i = 2; i < pin.Length; i++)
        {
            cyclic &= (pin[i] - pin[i - 1] + 10) % 10 == step;
        }
        if (cyclic) patterns |= PinPattern.CyclicSequence;

        for (int period = 2; period <= pin.Length / 2; period++)
        {
            if (pin.Length % period != 0) continue;
            bool repeatedPrefix = true;
            for (int i = period; i < pin.Length - 1; i++)
            {
                repeatedPrefix &= pin[i] == pin[i % period];
            }
            if (!repeatedPrefix) continue;
            if (pin[^1] != pin[(pin.Length - 1) % period])
            {
                patterns |= PinPattern.AlmostRepeatedBlock;
            }
            else if (period >= 5)
            {
                patterns |= PinPattern.LongRepeatedBlock;
            }
        }

        bool palindrome = true;
        for (int i = 0; i < pin.Length / 2; i++) palindrome &= pin[i] == pin[^(i + 1)];
        if (palindrome) patterns |= PinPattern.Palindrome;

        if (pin.Length >= 8 && pin.Length % 4 == 0)
        {
            bool years = true;
            for (int i = 0; i < pin.Length; i += 4) years &= IsPlausibleYear(pin.Slice(i, 4));
            if (years) patterns |= PinPattern.YearCombination;
        }
        if (pin.Length is 10 or 12
            && ((IsPlausibleDate(pin[..^4]) && IsPlausibleYear(pin[^4..]))
                || (IsPlausibleYear(pin[..4]) && IsPlausibleDate(pin[4..]))))
        {
            patterns |= PinPattern.DateYearCombination;
        }

        foreach (string digits in KnownConstantPrefixes)
        {
            if (digits.AsSpan().StartsWith(pin, StringComparison.Ordinal)) patterns |= PinPattern.KnownConstant;
        }
        if (IsStructuredKeypadWalk(pin, phoneLayout: true) || IsStructuredKeypadWalk(pin, phoneLayout: false))
        {
            patterns |= PinPattern.StructuredKeypadWalk;
        }
        return patterns;
    }

    private static bool IsStructuredKeypadWalk(ReadOnlySpan<char> pin, bool phoneLayout)
    {
        // Complete adjacent paths with at most two direction changes. An
        // arbitrary neighboring-key walk is deliberately not enough to match.
        int turns = 0, previousDx = 0, previousDy = 0;
        for (int i = 1; i < pin.Length; i++)
        {
            (int x1, int y1) = Position(pin[i - 1], phoneLayout);
            (int x2, int y2) = Position(pin[i], phoneLayout);
            int dx = x2 - x1, dy = y2 - y1;
            if (Math.Abs(dx) > 1 || Math.Abs(dy) > 1 || (dx == 0 && dy == 0)) return false;
            if (i > 1 && (dx != previousDx || dy != previousDy) && ++turns > 2) return false;
            previousDx = dx;
            previousDy = dy;
        }
        return true;
    }

    private static (int X, int Y) Position(char digit, bool phoneLayout)
    {
        if (digit == '0') return (phoneLayout ? 1 : 0, 3);
        int index = digit - '1';
        return (index % 3, phoneLayout ? index / 3 : 2 - index / 3);
    }

    private static bool IsPlausibleYear(ReadOnlySpan<char> digits) =>
        digits.Length == 4 && Number(digits) is >= FirstPlausibleYear and <= LastPlausibleYear;

    private static bool ContainsOnlyDigits(ReadOnlySpan<char> text)
    {
        foreach (char digit in text) if (digit is < '0' or > '9') return false;
        return true;
    }

    private static int Number(ReadOnlySpan<char> digits)
    {
        int value = 0;
        foreach (char digit in digits) value = value * 10 + digit - '0';
        return value;
    }
}
