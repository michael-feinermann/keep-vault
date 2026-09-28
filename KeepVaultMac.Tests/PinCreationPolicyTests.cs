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
        new("security.credential-encoding-only", "technical credential limits preserve raw input encoding under independent v13 domains", TestEncodingAsync, TestResource.Light, "Security"),
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

        // Independent Python hashlib.sha3_512 v13 vectors (credential_encoding_v13_reference.py):
        // all six historical v12 oracle values were reproduced before domain replacement.
        // LE32 byte lengths,
        // untouched UTF-8 password, ASCII PIN and the two separate factor halves.
        (string Password, string Pin, string Digest)[] fixtures =
        [
            ("", "", "505785BF3FCFB0E3710BFC8446E79588FF58009B9A45A1E22A182521B836E2E9BE2A38D456C276B72E1A3DCF89ED78CE77F4EBB36926C4375645A99571DCAA89BDE8B3647E38BE86FE00A54DBE3EEE351CF5538035CF245D7EABADAEF13E0389EA4D82479FCF8D95CFB8844E08FE0FA1A2EDDA74255241F2E754847A88FC7AB4"),
            ("p", "1", "F6ADD51BEE9BC3809AC72D729C629DA6F4491D575C9F1C976FF86474806859034CE42956E97B3BB90D7E0C569D537EC88D7C1FA8BE0C0D9F21731A7D3CE9318CD5CC5EAA74A56D2501EC8478E16939FBBBC9D67DC9241E1264A365DBCA93900EF698C12E5A297B2210D889569EAD5B6EF758EB041F516D9310F2CD45D4E918E7"),
            (new string('x', 257), new string('1', 17), "5096E10C7E2836948077031077DC17C9E8CE9AA45C87AB4AF0C98F29940EFA9AB3FD65FFD0D5D0CDEEF578F95631AAEA5371C323763D86556BE706B3B47F8CF8E69C012FF03407DE4B5C4E71BEE186C38A7595187F98B0EE456CFD7B4A9719028DF61C5DE042C38CC6E41A7FE47CA87A3AEAB35C65BFB2EE0C68FE31F50DE98D"),
            ("é", "0001", "212E651EC8CD8A06B49E70284FA45F6F89A517A5EA33333858B233CAB9D4C4943C8E87DF33D6CAB6999B488ED523524DB81804AA54BA902D74A514E3E7192684C4FF69152168FBF3363D43F1B692875C173842BD1DF747F0E9A2F9FF55445BB4DD40BCE51D8253E3D773F0AE99E9EF595FBE0AF5E05BA3E3FA8F163189816DEA"),
            ("e\u0301", "0001", "6EB30A5367B9BF88D6D573D1E2E9979AFEC43D37583A5AFE6361F1120C932886A500D0386B273B18A6D3B8AB07F208E0BBDDCFADB296E326621E1D736FB50955291699BAFA8D7E4C6550C8AD8C39A4B6A1100ACCAF57F09953E610DAD6B819C9E7C38CE9BDCCF61802E4D3D3112D2BC2B8F2B8D6F3FF5751C0ECB36BC60C98E2"),
            ("\ud800", "0", "12D9B28E472E9EB1B72612ADBCF771259169F70314B746B077ABA9F9C131574B29C867A4D9FCDABC5A2DF33A40815698FA9DF95CB7AAFCD165B82DB57FF3710A11CA0BE4F106A5B31A034A3DB856C526C41F3DAB849E5F2EF284257B85189178C66ED6DBC7A22B07A857B9EF16FFB568C2187A90601AB914A028EC40564AD0D6"),
        ];
        byte[] factorA = Enumerable.Range(0, 128).Select(i => (byte)i).ToArray();
        byte[] factorB = Enumerable.Range(0, 128).Select(i => (byte)(255 - i)).ToArray();
        byte[] actual = new byte[V13MasterKdf.CredentialHashBytes];
        try
        {
            foreach ((string password, string pin, string digest) in fixtures)
            {
                ContainerKeyDerivation.ValidatePasswordEncoding(password);
                ContainerKeyDerivation.ValidatePinEncoding(pin);
                V13MasterKdf.DeriveSha3CredentialHash(EncryptionSuiteCatalog.KalynaAlgorithm, password, pin, factorA, factorB, actual);
                byte[] expected = Convert.FromHexString(digest);
                try { Require(CryptographicOperations.FixedTimeEquals(expected, actual), "Technical-validation split changed the independently encoded v13 credential transcript."); }
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
