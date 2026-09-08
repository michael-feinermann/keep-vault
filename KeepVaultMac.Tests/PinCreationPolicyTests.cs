using System.Security.Cryptography;
using System.Text.RegularExpressions;
using KalynaArchiver.Services;

internal static class PinCreationPolicyTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("security.pin-password-pair", "literal complete PIN/password pairing and pending validation", TestPairAsync, TestResource.Light, "Security"),
        new("security.pin-local-dates", "local final dates, exact formats, leap years and versioned date bounds", TestDatesAsync, TestResource.Light, "Security"),
        new("security.pin-pattern-monotonicity", "additional complete PIN patterns retain every sampled historical rejection", TestPatternsAsync, TestResource.Light, "Security"),
        new("security.credential-encoding-only", "technical credential limits preserve historical v12 byte encodings", TestEncodingAsync, TestResource.Light, "Security"),
    ];

    private static readonly DateOnly FixedDate = new(2026, 9, 6);
    private const string UnrelatedPassword = "Independent PIN policy fixture, no digit substring.";

    private static PinPolicyAnalysis Analyze(string pin, string? password = UnrelatedPassword) =>
        ContainerKeyDerivation.AnalyzePinForCreation(pin, password, FixedDate);

    private static Task TestPairAsync()
    {
        foreach (string password in new[] { "583104Suffix", "Prefix583104Suffix", "Prefix583104", "583104" })
        {
            PinPolicyAnalysis result = Analyze("583104", password);
            Require(result.PairCheckComplete && result.Violations.Contains(PinPolicyViolation.ContainedInPassword), "Literal full-PIN match was not rejected.");
        }
        Require(Analyze("0583104", "Text0583104Ende").Violations.Contains(PinPolicyViolation.ContainedInPassword), "Leading-zero PIN match was missed.");
        foreach (string password in new[] { "Text583-104Ende", "Text58\u200b3104Ende", "Text５８３１０４Ende", "Text58310Ende" })
        {
            Require(!Analyze("583104", password).Violations.Contains(PinPolicyViolation.ContainedInPassword), "Pair checking normalized or joined separate digits.");
        }
        Require(!Analyze("0583104", "Text583104Ende").Violations.Contains(PinPolicyViolation.ContainedInPassword), "Pair checking removed the leading zero.");
        foreach (string? missing in new string?[] { null, string.Empty })
        {
            PinPolicyAnalysis result = Analyze("583104", missing);
            Require(!result.IsAccepted && !result.PairCheckComplete && result.Violations.Contains(PinPolicyViolation.PasswordRequiredForPairCheck), "An incomplete pair was marked accepted.");
        }
        Require(!ContainerKeyDerivation.AnalyzePinForCreation("583104").PairCheckComplete, "PIN-only preview confirmed a password pair.");
        foreach (string? missingOrInvalid in new string?[] { null, string.Empty, "12", "58310458310458310", "58310x", "１２３４５６" })
        {
            PinPolicyAnalysis result = ContainerKeyDerivation.AnalyzePinForCreation(missingOrInvalid, UnrelatedPassword, FixedDate);
            Require(!result.PairCheckComplete, "Missing or malformed PIN confirmed a password pair.");
            Require(!result.Violations.Contains(PinPolicyViolation.PasswordRequiredForPairCheck), "A present password was reported missing because the PIN was invalid.");
        }
        PinPolicyAnalysis weakPair = Analyze("123456");
        Require(weakPair.PairCheckComplete && !weakPair.IsAccepted, "PIN quality rejection was confused with an incomplete pair check.");
        Require(Analyze("583104").IsAccepted, "Unrelated pair control was rejected.");
        Require(!Analyze("583104", "Updated583104Password").IsAccepted, "Changed password reused stale pair approval.");
        Require(Analyze("583104").IsAccepted, "Removing the substring did not recompute pair validation.");
        return Task.CompletedTask;
    }

    private static Task TestDatesAsync()
    {
        foreach (string pin in new[] { "060926", "06092026", "090626", "09062026" })
        {
            PinPolicyAnalysis result = Analyze(pin);
            Require(result.Violations.Count(v => v == PinPolicyViolation.CurrentDate) == 1, "A mandatory current-date format was missing or duplicated.");
        }
        foreach (string pin in new[] { "20260906", "260906", "4810609267295083" })
        {
            Require(!Analyze(pin).Violations.Contains(PinPolicyViolation.CurrentDate), "Current-date equality broadened beyond its four exact formats.");
        }
        foreach (string pin in new[] { "060626", "06062026" })
        {
            PinPolicyAnalysis result = ContainerKeyDerivation.AnalyzePinForCreation(pin, UnrelatedPassword, new DateOnly(2026, 6, 6));
            Require(result.Violations.Count(v => v == PinPolicyViolation.CurrentDate) == 1, "Duplicate date formats created duplicate violations.");
        }

        foreach (string date in new[] { "010190", "31121999", "19900101", "12311999", "991231", "290200", "022900", "000229", "29022000", "20560229" })
        {
            Require(PinCreationPatterns.IsPlausibleDate(date), "A valid full calendar-date vector was missed.");
        }
        foreach (string date in new[] { "29021900", "310499", "29022026", "31042026", "01321999", "000000", "01011899", "20570101", "20570229", "１２３１９９", "4810609267295083" })
        {
            Require(!PinCreationPatterns.IsPlausibleDate(date), "Invalid, out-of-model or partial date matched.");
        }

        var west = TimeZoneInfo.CreateCustomTimeZone("pin-test-west", TimeSpan.FromHours(-7), "test", "test");
        var east = TimeZoneInfo.CreateCustomTimeZone("pin-test-east", TimeSpan.FromHours(2), "test", "test");
        DateTimeOffset instant = new(2026, 9, 6, 0, 30, 0, TimeSpan.Zero);
        Require(ContainerKeyDerivation.LocalCreationDate(new FixedClock(instant, west)) == new DateOnly(2026, 9, 5), "Local date used UTC instead of the configured timezone.");
        Require(ContainerKeyDerivation.LocalCreationDate(new FixedClock(instant, east)) == FixedDate, "Positive timezone offset changed the wrong calendar day.");
        var before = new FixedClock(new DateTimeOffset(2026, 9, 5, 21, 59, 59, TimeSpan.Zero), east);
        var after = new FixedClock(new DateTimeOffset(2026, 9, 5, 22, 0, 0, TimeSpan.Zero), east);
        Require(!ContainerKeyDerivation.AnalyzePinForCreation("060926", UnrelatedPassword, ContainerKeyDerivation.LocalCreationDate(before)).Violations.Contains(PinPolicyViolation.CurrentDate), "Pre-midnight test used the following day.");
        Require(ContainerKeyDerivation.AnalyzePinForCreation("060926", UnrelatedPassword, ContainerKeyDerivation.LocalCreationDate(after)).Violations.Contains(PinPolicyViolation.CurrentDate), "Final check reused the previous day's result.");
        Require(PinCreationPatterns.IsCurrentDate("01019999", new DateOnly(9999, 1, 1)), "Current-date rule incorrectly depends on the fixed plausible-year range.");
        return Task.CompletedTask;
    }

    private static Task TestPatternsAsync()
    {
        (string Pin, PinPattern Pattern)[] vectors =
        [
            ("024680", PinPattern.CyclicSequence),
            ("4283142831", PinPattern.LongRepeatedBlock),
            ("4283142832", PinPattern.AlmostRepeatedBlock),
            ("42833824", PinPattern.Palindrome),
            ("20042008", PinPattern.YearCombination),
            ("2902001984", PinPattern.DateYearCombination),
            ("271828", PinPattern.KnownConstant),
            ("3141592653589793", PinPattern.KnownConstant),
            ("085236", PinPattern.StructuredKeypadWalk), // phone zero below 8
            ("014789", PinPattern.StructuredKeypadWalk), // keypad zero below 1
        ];
        foreach ((string pin, PinPattern expected) in vectors)
        {
            PinPolicyAnalysis result = Analyze(pin);
            Require((result.Patterns & expected) != 0 && !result.IsAccepted, "Additional complete PIN pattern was missed.");
        }
        Require((PinCreationPatterns.Analyze("125896") & PinPattern.StructuredKeypadWalk) == 0, "Arbitrary adjacent paths were treated as structured walks.");
        Require(PinCreationPatterns.Analyze("4810609267295083") == PinPattern.None, "An embedded date alone triggered a whole-PIN pattern rule.");

        string[] previousValid = ["428317", "84920153", "19482736", "3819405627", "9274018365", "1948273645019", "92740183652847", "381940562718294", "4283179501628374"];
        foreach (string pin in previousValid) Require(Analyze(pin).IsAccepted, "An irregular historical positive control unexpectedly failed.");

        // Independent declarative oracle for the old creation exclusions.
        // No production predicate is reused in deciding which samples must fail.
        var syntax = new Regex("\\A[0-9]{6,16}\\z", RegexOptions.CultureInvariant);
        var triples = new Regex("([0-9])\\1\\1", RegexOptions.CultureInvariant);
        var repetition = new Regex("\\A([0-9]{2,4})\\1+\\z", RegexOptions.CultureInvariant);
        var pairs = new Regex("\\A(?:00|11|22|33|44|55|66|77|88|99)+\\z", RegexOptions.CultureInvariant);
        string[] forbiddenTriples = "012 123 234 345 456 567 678 789 987 876 765 654 543 432 321 210 036 147 258 369 630 741 852 963 048 159 840 951 357 753".Split(' ');
        string[] blocklist = "121212 12121212 1212121212 121212121212 131313 141414 151515 161616 171717 181818 191919 202020 696969 112233 11223344 123123 12341234 1234512345 246810 135791 987654 654321 123456 012345 543210 147258 258147 369258 159357 753951 159753 357159 258025 147014 369036 741852 963852 852963 789456 456123 000000 111111 222222 333333 444444 555555 666666 777777 888888 999999".Split(' ');
        bool OldRejects(string pin) => !syntax.IsMatch(pin) || pin.Distinct().Count() < 4 || triples.IsMatch(pin)
            || repetition.IsMatch(pin) || pairs.IsMatch(pin) || blocklist.Contains(pin, StringComparer.Ordinal)
            || forbiddenTriples.Any(triple => pin.Contains(triple, StringComparison.Ordinal));
        foreach (string pin in blocklist.Concat(new[] { "", "12345", "12345678901234567", "12a456", "１２３４５６", "12 456", "112211" }))
        {
            Require(OldRejects(pin) && !Analyze(pin).IsAccepted, "Historical explicit rejection became accepted.");
        }
        var random = new Random(0x501502);
        int rejected = 0, accepted = 0;
        for (int sample = 0; sample < 20_000; sample++)
        {
            int length = 6 + sample % 11;
            char[] digits = new char[length];
            for (int i = 0; i < length; i++) digits[i] = (char)('0' + random.Next(10));
            string pin = new(digits);
            PinPolicyAnalysis result = Analyze(pin);
            if (OldRejects(pin))
            {
                rejected++;
                Require(!result.IsAccepted, "A historical rejection became accepted in the deterministic corpus.");
            }
            if (result.IsAccepted) accepted++;
        }
        Require(rejected > 1000 && accepted > 1000, "Monotonicity corpus did not exercise both outcomes.");
        return Task.CompletedTask;
    }

    private static Task TestEncodingAsync()
    {
        foreach (string pin in new[] { "", "1", "0001", "12345678901234567", new string('1', ContainerKeyDerivation.MaxCredentialCodeUnits) })
            ContainerKeyDerivation.ValidatePinEncoding(pin);
        foreach (string password in new[] { "", "p", new string('x', 257), "\ud800", new string('x', ContainerKeyDerivation.MaxCredentialCodeUnits) })
            ContainerKeyDerivation.ValidatePasswordEncoding(password);
        foreach (string? pin in new string?[] { null, "1a", "1 2", "１２", "١٢", "\ud800", new string('1', ContainerKeyDerivation.MaxCredentialCodeUnits + 1) })
            RequireThrows(() => ContainerKeyDerivation.ValidatePinEncoding(pin));
        RequireThrows(() => ContainerKeyDerivation.ValidatePasswordEncoding(null));
        RequireThrows(() => ContainerKeyDerivation.ValidatePasswordEncoding(new string('x', ContainerKeyDerivation.MaxCredentialCodeUnits + 1)));
        RequireThrows(() => ContainerKeyDerivation.ValidatePinSyntax("1"));
        RequireThrows(() => ContainerKeyDerivation.ValidatePinSyntax("12345678901234567"));

        // Independent Python hashlib.sha3_512 vectors: LE32 byte lengths,
        // untouched UTF-8 password, ASCII PIN and the two separate factor halves.
        (string Password, string Pin, string Digest)[] fixtures =
        [
            ("", "", "106B5E40437B0F00774B071193AF68BA031AC1AC55D45C64B842A8529D96F8076F25A6C3F339698835E8724F4ADC9AABFB0D0D269FBF8717E5BE3B31FE4E696ADE0E255E7C342F871D727B47B03E4739DC0AF8A7D911C15E8B3E6175D1395492E68D72BEE161BB05CCE5D2BFDD6274B94669A848F3D9558B6377EDC68F662677"),
            ("p", "1", "F17D86C07105DC096A07D2AE7F649161A208DE7D333B66367E53EF7659DA066596DBC62227A591176D09318B80E6050B7FAE55996BB0881826691A9250CA1826C6C2905CC8D5A09184F386849608FF5D42B12449B2AF73ACBE9C902214DBF217F1A5234F4A716BBB877D853B1D3A3E98857A63B455448FF6ADA7AC07C18983E2"),
            (new string('x', 257), new string('1', 17), "557DC8DAB9806D5B0985504D163F6425C25249ABB058D7739C2657FFB2A2EF3569888482F689D82C337B9234140B7BE8708E7D2CB5B4EDAE780FC39C3EECB45C369FB2B047083B7B90FA81212424436587C8A45D18ADB4301C9131F4288B923C1160586B0EFA19FD771E6639DAE0FBE6ECA9595717D65CEFA5C7A4FB76A39E83"),
            ("é", "0001", "DF41C16F4CE3F8849AA4FEF93A733A60D4CE38B587ED06CE8929131FF7AD8F1FC51B6634A08BA07CBB7ABD6153B3582A4DCCB403AD81DF6045C1D3395E629E2C0599CE134A7623447B49F1E6550021ED9C4035D909B6F508BE979036CBABE88B8402DD9CF6894729446F2BE4538E40603274E5A911906EB067472A1A600F5CD3"),
            ("e\u0301", "0001", "31A3B06B3D76EFE46288579424629AF65602F96CE1CC04A199697309CDA2B67570D995900B2E8F1DFA19A64C294B8709ACF363D35E14896EB0579C5654646B9DDA4C3CDE3BD97C4DA211BBB456ACFD297584DAD7C4026BDBA9B1BC04DB50FC84F5F3CB8B5F40F0DF37AA449579BED7CF4BF04DFD281088A56D9D3A36CF639088"),
            ("\ud800", "0", "FCBCEDFD29D9731FF921C904955C0A0E8978CF2C80BA619C814628FC97848C3A519BE0BA9EF18A7F63B45951E0959A05F2CB3F9D8C68C5B4717791E74BCE6132185B70FBA90DDCC5071FB5FE7172412399A59AD7F646DE81CE00260854C486B89673185F569E1E305FD8CC003A0E0C5CE7509DA09F0EF0F20FE2EEE1A19E9D93"),
        ];
        byte[] factorA = Enumerable.Range(0, 128).Select(i => (byte)i).ToArray();
        byte[] factorB = Enumerable.Range(0, 128).Select(i => (byte)(255 - i)).ToArray();
        byte[] actual = new byte[V12MasterKdf.CredentialHashBytes];
        try
        {
            foreach ((string password, string pin, string digest) in fixtures)
            {
                ContainerKeyDerivation.ValidatePasswordEncoding(password);
                ContainerKeyDerivation.ValidatePinEncoding(pin);
                V12MasterKdf.DeriveSha3CredentialHash(EncryptionSuiteCatalog.KalynaAlgorithm, password, pin, factorA, factorB, actual);
                byte[] expected = Convert.FromHexString(digest);
                try { Require(CryptographicOperations.FixedTimeEquals(expected, actual), "Technical-validation split changed v12 credential input bytes."); }
                finally { CryptographicOperations.ZeroMemory(expected); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(factorA);
            CryptographicOperations.ZeroMemory(factorB);
            CryptographicOperations.ZeroMemory(actual);
        }
        return Task.CompletedTask;
    }

    private sealed class FixedClock(DateTimeOffset instant, TimeZoneInfo zone) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => instant;
        public override TimeZoneInfo LocalTimeZone => zone;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private static void RequireThrows(Action action)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        throw new InvalidOperationException("Invalid technical input was accepted.");
    }
}
