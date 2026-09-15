using System.IO;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using KalynaArchiver.Services;

internal static class PasswordModelReferenceTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("security.password-model-data", "offline model integrity, completeness and fail-closed resources", TestPasswordModelDataAsync, TestResource.Light, "Security"),
        new("security.password-model-phrases", "complete password-model phrase and formatting bounds", TestPasswordModelPhrasesAsync, TestResource.Light, "Security"),
        new("security.password-model-bip39", "independent BIP39 checksum and format vectors", TestPasswordModelBip39Async, TestResource.Light, "Security"),
        new("security.password-model-boundaries", "legacy policy, Unicode and model boundaries", TestPasswordModelBoundariesAsync, TestResource.Light, "Security"),
        new("security.password-model-isolation", "model guard isolation across async contexts", TestPasswordModelIsolationAsync, TestResource.Light, "Security"),
        new("security.password-model-bounded", "bounded offline password-model execution", TestPasswordModelBoundedAsync, TestResource.Light, "Security"),
    ];
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static Task TestPasswordModelDataAsync()
    {
        PasswordModelData data = PasswordModelData.Load();
        Require(data.Lists["eff-en.txt"].Length == 7776 && data.Lists["diceware-de.txt"].Length == 7776
            && data.Lists["bip39-en.txt"].Length == 2048, "The three required word-list sizes changed.");
        Require(data.Bip39Indices["abandon"] == 0 && data.Bip39Indices["zoo"] == 2047,
            "Canonical BIP39 ordering was lost.");
        Require(data.Blocklist.Count >= 30000 && data.Words.Count > 60000 && data.NormalizedCollisions > 0,
            "The ranked dictionaries, limited blocklist, or overlap handling are incomplete.");

        string[] critical = ["manifest.json", "eff-en.txt", "diceware-de.txt", "bip39-en.txt", "rank-de.txt", "rank-en.txt", "passwords.txt", "LICENSE-bip39.txt"];
        foreach (string file in critical)
        {
            PasswordGuessabilityAnalysis missing = PasswordGuessabilityService.EvaluateWithResourcesForTesting(
                "Synthetic test input with missing model 2026!", 200,
                name => name == file ? null : PasswordModelData.OpenEmbeddedResource(name));
            Require(missing.Status == PasswordModelStatus.Unavailable && missing.CompleteModelBits is null,
                "Missing analysis data did not fail closed: " + file);
            PasswordGuessabilityAnalysis corrupt = PasswordGuessabilityService.EvaluateWithResourcesForTesting(
                "Synthetic test input with corrupt model 2026!", 200, name =>
                {
                    Stream? original = PasswordModelData.OpenEmbeddedResource(name);
                    if (name != file || original is null) return original;
                    using (original)
                    using (var copy = new MemoryStream())
                    {
                        original.CopyTo(copy);
                        byte[] bytes = copy.ToArray(); bytes[bytes.Length / 2] ^= 1;
                        return new MemoryStream(bytes, writable: false);
                    }
                });
            Require(corrupt.Status == PasswordModelStatus.Unavailable && corrupt.CompleteModelBits is null,
                "Corrupt analysis data did not fail closed: " + file);
        }
        PasswordGuessabilityAnalysis oversized = PasswordGuessabilityService.EvaluateWithResourcesForTesting(
            "Synthetic test input with oversized model!", 200, _ => new MemoryStream(new byte[2 * 1024 * 1024 + 1], writable: false));
        Require(oversized.Status == PasswordModelStatus.Unavailable, "Oversized model data was not rejected.");
        return Task.CompletedTask;
    }

    private static Task TestPasswordModelPhrasesAsync()
    {
        foreach ((string input, double oldScore) in new[]
        {
            ("Sommer Wiese Mond Vulkan Fluss Orange Wolke 2026!", 144.3),
            ("SommerWieseMondVulkanFlussOrangeWolke2026!", 129.2),
        })
        {
            PasswordPolicyAnalysis analysis = PasswordKeyService.AnalyzeUserPassword(input);
            Require(analysis.Guessability is { Status: PasswordModelStatus.Available }, "The supplementary model was not applied.");
            Require(Math.Abs(analysis.Guessability!.PreviousConservativeBits - oldScore) < 0.00001,
                "The pre-existing estimator changed instead of remaining the independent upper bound.");
            Require(analysis.ConservativeEntropyBits < 128 && !analysis.IsAccepted
                && analysis.Violations.Contains(PasswordPolicyViolation.InsufficientConservativeEntropy),
                "A previously overestimated German passphrase was accepted.");
        }

        string[] constructions =
        [
            "SommerWieseMondVulkanFlussOrangeWolke2026!",
            "SOMMER_WIESE_MOND_VULKAN_FLUSS_ORANGE_WOLKE2026!",
            "S0mmerWieseM0ndVulk4nFluss0r4ngeW0lke2026!",
            "WinterGardenRiverMountainCloudOrange2026!",
            "MichaelSommerHausAuto2026!",
            "Vulkanheit Unvulkan Vulkanungen 2026!",
            "Häuser Häusern Sommer Flüsse Grüße 2026!",
            "Haеuser Sommer Mond 2026!", // Cyrillic e is an unknown remainder, not silently Latinized.
            "correct horse battery staple 2026!",
        ];
        foreach (string input in constructions)
        {
            PasswordGuessabilityAnalysis analysis = PasswordGuessabilityService.Evaluate(input, 500);
            Require(analysis.Status == PasswordModelStatus.Available && analysis.CompleteModelBits is > 0 and < 200,
                "A complete structured construction was not bounded by the offline model.");
            Require(!analysis.IsEmpiricallyCalibrated, "An uncalibrated score was promoted to empirical evidence.");
        }
        foreach (string input in constructions.Take(3))
        {
            PasswordPolicyAnalysis analysis = PasswordKeyService.AnalyzeUserPassword(input);
            Require(!analysis.IsAccepted && analysis.ConservativeEntropyBits < 128
                && analysis.Guessability is not null && analysis.ConservativeEntropyBits <= analysis.Guessability.PreviousConservativeBits,
                "A simple case/leet/year variant escaped the corrected 128-bit creation threshold.");
        }
        string ordinary = constructions[0];
        string interleaved = string.Join("\u200b", Enumerable.Range(0, (ordinary.Length + 1) / 2)
            .Select(index => ordinary.Substring(index * 2, Math.Min(2, ordinary.Length - index * 2))));
        PasswordPolicyAnalysis hidden = PasswordKeyService.AnalyzeUserPassword(interleaved);
        Require(hidden.Guessability?.PreviousConservativeBits >= 128 && hidden.ConservativeEntropyBits < 128 && !hidden.IsAccepted,
            "A completely reconstructible periodic invisible-format variant escaped phrase analysis.");
        Require(hidden.Guessability?.ModelFamily == "complete-periodic-format-variant", "The format correction was not a complete declared transformation.");
        VerifyPasswordFormatCandidateMinimum(ordinary);
        string prefix = "SommerWieseMond";
        PasswordGuessabilityAnalysis shortRest = PasswordGuessabilityService.Evaluate(prefix + "!", 500);
        PasswordGuessabilityAnalysis longRest = PasswordGuessabilityService.Evaluate(prefix + "🦊🛰️🧬🦉🪐🦑🐙🦋🦎🐳", 500);
        Require(longRest.CompleteModelBits > shortRest.CompleteModelBits + 60 && longRest.UnknownCodepoints >= 10,
            "A recognized prefix discarded the unknown complete suffix.");
        foreach (string input in new[] { "größere Häuser Wolken 2026!", "GRÖSSERE HAEUSER WOLKEN 2026!" })
        {
            string decomposed = input.Normalize(NormalizationForm.FormD);
            byte[] before = Encoding.UTF8.GetBytes(decomposed);
            PasswordGuessabilityAnalysis value = PasswordGuessabilityService.Evaluate(decomposed, 500);
            Require(value.Status == PasswordModelStatus.Available && value.CompleteModelBits < 150,
                "A canonical analysis variant escaped word recognition.");
            Require(before.SequenceEqual(Encoding.UTF8.GetBytes(decomposed)), "Analysis changed the original password bytes.");
        }
        return Task.CompletedTask;
    }

    private static void VerifyPasswordFormatCandidateMinimum(string ordinary)
    {
        PasswordModelData data = PasswordModelData.Load();
        MethodInfo withoutFormats = typeof(PasswordGuessabilityService).GetMethod("EvaluateData", BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo variants = typeof(PasswordGuessabilityService).GetMethod("UniformFormatVariants", BindingFlags.Static | BindingFlags.NonPublic)!;
        PasswordGuessabilityAnalysis Base(string input) => (PasswordGuessabilityAnalysis)withoutFormats.Invoke(null, [input, 1000d, data, false])!;
        string Interleave(string input, char marker) => string.Join(marker,
            Enumerable.Range(0, (input.Length + 1) / 2).Select(index => input.Substring(index * 2, Math.Min(2, input.Length - index * 2))));
        char[] alphabet = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff', '\u00ad', '\u2063', '\u2062'];
        for (int index = 0; index < alphabet.Length; index++)
        {
            char periodic = alphabet[index], earlier = alphabet[(index + 1) % alphabet.Length];
            string basis = earlier + ordinary;
            // The first marker is a competing single-position strategy. The later marker has
            // a fully valid period-2 placement that includes the retained first marker.
            string input = Interleave(basis, periodic);
            string singleRemoval = input.Replace(earlier.ToString(), string.Empty, StringComparison.Ordinal);
            double periodicCost = Base(basis).CompleteModelBits!.Value + Math.Log2(8 * 3 * 2);
            double singleCost = Base(singleRemoval).CompleteModelBits!.Value + Math.Log2(8 * (singleRemoval.Length + 1.0));
            double expected = Math.Min(Base(input).CompleteModelBits!.Value, Math.Min(periodicCost, singleCost));
            PasswordGuessabilityAnalysis actual = PasswordGuessabilityService.Evaluate(input, 1000);
            Require(Math.Abs(actual.CompleteModelBits!.Value - expected) < 0.00001
                && periodicCost < singleCost && actual.UnknownCodepoints >= 1,
                "An earlier format scalar hid the lower applicable complete strategy, or the retained scalar was discarded.");
            var recognized = (IEnumerable<(string Text, double Bits)>)variants.Invoke(null, [input])!;
            Require(recognized.Count() == 2, "Not every applicable alphabet member was enumerated.");
        }
        // A bare prefix changes the period's start position. It is outside the declared three
        // placement modes; never make it match by dropping an unpriced offset or a second family.
        string barePrefix = "\u2060" + Interleave(ordinary, '\u200b');
        var bareVariants = ((IEnumerable<(string Text, double Bits)>)variants.Invoke(null, [barePrefix])!).ToArray();
        Require(bareVariants.Length == 1 && bareVariants[0].Text.Contains('\u200b'),
            "A non-applicable offset or nested format removal became an unpriced strategy.");
        PasswordGuessabilityAnalysis bare = PasswordGuessabilityService.Evaluate(barePrefix, 1000);
        double bareExpected = Math.Min(Base(barePrefix).CompleteModelBits!.Value,
            Base(bareVariants[0].Text).CompleteModelBits!.Value + bareVariants[0].Bits);
        Require(Math.Abs(bare.CompleteModelBits!.Value - bareExpected) < 0.00001 && bare.UnknownCodepoints > 1,
            "A second format family was applied despite the single-family bound.");
    }

    private static Task TestPasswordModelBip39Async()
    {
        PasswordModelData data = PasswordModelData.Load();
        foreach ((string entropyHex, string mnemonic) in PasswordModelBip39Vectors)
        {
            int expectedEntropy = entropyHex.Length * 4;
            PasswordGuessabilityAnalysis analysis = PasswordGuessabilityService.Evaluate(mnemonic, 500);
            Require(analysis.Bip39ChecksumValid && analysis.Bip39EntropyBits == expectedEntropy
                && analysis.CompleteModelBits <= expectedEntropy,
                "A published/independently generated BIP39 checksum vector failed.");
            string[] words = mnemonic.Split(' ');
            int finalIndex = data.Bip39Indices[words[^1]];
            words[^1] = data.Lists["bip39-en.txt"][finalIndex ^ 1];
            PasswordGuessabilityAnalysis invalid = PasswordGuessabilityService.Evaluate(string.Join(' ', words), 500);
            Require(!invalid.Bip39ChecksumValid && invalid.Bip39EntropyBits is null,
                "A checksum-only bit mutation was incorrectly accepted.");
            Require(invalid.CompleteModelBits <= words.Length * 11,
                "Invalid BIP39 checksums lost the still-applicable complete word-list cap.");
            string title = string.Join(' ', mnemonic.Split(' ').Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
            foreach (string formatted in new[] { title, mnemonic.ToUpperInvariant() })
            {
                PasswordGuessabilityAnalysis value = PasswordGuessabilityService.Evaluate(formatted, 500);
                Require(value.Bip39ChecksumValid && value.Bip39EntropyBits == expectedEntropy
                    && value.CompleteModelBits <= expectedEntropy + 2.00001,
                    "A uniform BIP39 case format lost the checksum-derived complete cap.");
            }
            foreach (string formatted in new[] { mnemonic.Replace(' ', '-'), mnemonic.Replace(' ', '_'), mnemonic.Replace(" ", string.Empty, StringComparison.Ordinal) })
            {
                PasswordGuessabilityAnalysis value = PasswordGuessabilityService.Evaluate(formatted, 500);
                Require(value.Bip39ChecksumValid && value.Bip39EntropyBits == expectedEntropy
                    && value.CompleteModelBits <= expectedEntropy + 3.00001,
                    "A fixed separator/concatenated BIP39 format lost the checksum-derived complete cap.");
            }
            foreach (string withRest in new[] { mnemonic + "2026!", mnemonic + " 2026!", "2026! " + mnemonic })
            {
                PasswordGuessabilityAnalysis value = PasswordGuessabilityService.Evaluate(withRest, 500);
                Require(!value.Bip39ChecksumValid && value.Bip39EntropyBits is null
                    && value.CompleteModelBits <= expectedEntropy + 40,
                    "A BIP39 component discarded its suffix/prefix or lost the whole-construction checksum strategy.");
            }
            PasswordGuessabilityAnalysis invalidWithRest = PasswordGuessabilityService.Evaluate(string.Join(' ', words) + "2026!", 500);
            Require(!invalidWithRest.Bip39ChecksumValid && invalidWithRest.Bip39EntropyBits is null,
                "A checksum mutation plus suffix was mislabeled as a complete valid mnemonic.");
            Require(HasPasswordModelBip39Component(mnemonic + "2026!", mnemonic.Length, expectedEntropy, data)
                && !HasPasswordModelBip39Component(string.Join(' ', words) + "2026!", string.Join(' ', words).Length, expectedEntropy, data),
                "The actual checksum component path ignored a valid base or accepted its checksum-only mutation.");
        }
        foreach ((string name, int count) in new[] { ("eff-en.txt", 7776), ("diceware-de.txt", 7776), ("bip39-en.txt", 2048) })
        {
            string[] chosen = new[] { 173, 691, 1021, 1473, 1911, 2017 }.Select(index => data.Lists[name][index]).ToArray();
            foreach (string input in new[] { string.Join(' ', chosen), string.Join('-', chosen), string.Concat(chosen) })
            {
                PasswordGuessabilityAnalysis analysis = PasswordGuessabilityService.Evaluate(input, 500);
                Require(analysis.CompleteModelBits <= chosen.Length * Math.Log2(count) + 0.00001,
                    "A fixed-representation word-list space gained artificial character/separator entropy.");
            }
            string title = string.Join(' ', chosen.Select(word => char.ToUpperInvariant(word[0]) + word[1..]));
            Require(PasswordGuessabilityService.Evaluate(title, 500).CompleteModelBits <= chosen.Length * Math.Log2(count) + 2.00001,
                "Uniform title capitalization was counted as independent choices for every word.");
        }
        Require(PasswordGuessabilityService.Evaluate("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", 500).ExactBlocklistMatch,
            "The public zero-entropy mnemonic example was absent from the limited blocklist.");
        Require(!PasswordGuessabilityService.Evaluate("correct horse battery staple with a separately modelled remainder!", 500).ExactBlocklistMatch,
            "A dictionary substring was treated as an exact whole-password blocklist match.");
        return Task.CompletedTask;
    }

    private static bool HasPasswordModelBip39Component(string input, int end, int entropy, PasswordModelData data)
    {
        // Inspect the real private component matcher without adding a production bypass or
        // pretending a public zero-entropy example must choose the checksum path as its minimum.
        MethodInfo wordMatcher = typeof(PasswordGuessabilityService).GetMethod("MatchBip39Words", BindingFlags.NonPublic | BindingFlags.Static)!;
        MethodInfo componentMatcher = typeof(PasswordGuessabilityService).GetMethod("MatchBip39Components", BindingFlags.NonPublic | BindingFlags.Static)!;
        object words = wordMatcher.Invoke(null, [input, input.ToLowerInvariant(), data])!;
        object edges = Activator.CreateInstance(componentMatcher.GetParameters()[3].ParameterType)!;
        componentMatcher.Invoke(null, [input, 0, words, edges]);
        foreach (object edge in (System.Collections.IEnumerable)edges)
            if ((int)edge.GetType().GetProperty("End")!.GetValue(edge)! == end
                && (int?)edge.GetType().GetProperty("Bip39Entropy")!.GetValue(edge) == entropy) return true;
        return false;
    }

    private static Task TestPasswordModelBoundariesAsync()
    {
        Require(PasswordKeyService.MinimumConservativeEntropyBits == 128
            && PasswordKeyService.MinPasswordLength == 24 && PasswordKeyService.MaxPasswordLength == 256,
            "An existing password policy threshold changed.");
        foreach ((string input, PasswordPolicyViolation expected) in new[]
        {
            ("short", PasswordPolicyViolation.TooShort),
            (new string('x', 257), PasswordPolicyViolation.TooLong),
            ("SyntheticLongPasswordWithControl2026!\n", PasswordPolicyViolation.ControlCharacter),
            ("SyntheticLongPasswordInvalid2026!\ud800", PasswordPolicyViolation.InvalidUnicode),
            ("onlylowercaselettersandnothingelse", PasswordPolicyViolation.NotEnoughCharacterClasses),
            ("Ax1!Ax1!Ax1!Ax1!Ax1!Ax1!Ax1!", PasswordPolicyViolation.NotEnoughDistinctCharacters),
            ("0123456789abcdef0123456789abcdef", PasswordPolicyViolation.NotEnoughNonHexCharacters),
            ("SyntheticPasswordWithDEADBEEFand2026!", PasswordPolicyViolation.HexadecimalRunTooLong),
        })
            Require(PasswordKeyService.AnalyzeUserPassword(input).Violations.Contains(expected), "A previous rejection disappeared: " + expected);
        string strong = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
        Require(PasswordKeyService.AnalyzeUserPassword(strong).IsAccepted, "An unrelated strong synthetic password was rejected.");
        foreach (double previous in new[] { 0, 127.999, 128, 128.001, 200 })
        {
            PasswordGuessabilityAnalysis analysis = PasswordGuessabilityService.Evaluate(strong, previous);
            Require(analysis.CorrectedBits == previous && analysis.CorrectedBits <= analysis.PreviousConservativeBits,
                "Supplementary analysis raised or rounded the inherited 128-bit boundary.");
        }
        foreach (string sample in PasswordModelSyntheticCorpus())
        {
            PasswordPolicyAnalysis analysis = PasswordKeyService.AnalyzeUserPassword(sample);
            Require(analysis.Guessability is not null && analysis.ConservativeEntropyBits <= analysis.Guessability.PreviousConservativeBits,
                "A model raised the pre-existing conservative score.");
        }
        MethodInfo date = typeof(PasswordGuessabilityService).GetMethod("IsDate", BindingFlags.Static | BindingFlags.NonPublic)!;
        MethodInfo keyboard = typeof(PasswordGuessabilityService).GetMethod("KeyboardBits", BindingFlags.Static | BindingFlags.NonPublic)!;
        foreach (string value in new[] { "290200", "022900", "20000229", "29.02.2000", "2000-02-29", "31121999", "123199" })
            Require((bool)date.Invoke(null, [value])!, "A real calendar date was not recognized.");
        foreach (string value in new[] { "29021900", "290299", "31042026", "20260230", "2.9.0.2000", "2026/02-01", "01012100" })
            Require(!(bool)date.Invoke(null, [value])!, "An impossible or malformed calendar date was recognized.");
        foreach ((string plain, string shifted) in new[] { ("1q2w3e4r", "!q@w#e$r"), ("1q2w3e4r", "!q\"w§e$r"), ("qwerty", "QWERTY"), ("qwertz", "QWERTZ") })
        {
            double? original = (double?)keyboard.Invoke(null, [plain]);
            double? variant = (double?)keyboard.Invoke(null, [shifted]);
            Require(original is not null && variant >= original && variant < original + shifted.Length + 3,
                "Physical QWERTY/QWERTZ Shift keys escaped the keyboard model or gained an independent alphabet.");
        }
        return Task.CompletedTask;
    }

    private static async Task TestPasswordModelIsolationAsync()
    {
        _ = PasswordGuessabilityService.Evaluate("Synthetic model already loaded 2026!", 200);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task outside = Task.Run(async () =>
        {
            await release.Task.ConfigureAwait(false);
            Require(PasswordGuessabilityService.Evaluate("Outside isolated guard synthetic input!", 200).Status == PasswordModelStatus.Available,
                "An unrelated async context inherited the model guard.");
        });
        int attempts = 0;
        using (PasswordGuessabilityService.ForbidEvaluationForTesting(() => Interlocked.Increment(ref attempts)))
        {
            foreach (string invalid in new[] { "", "short", new string('x', 257), "Synthetic invalid UTF16 password!\ud800", "Synthetic control password!\n" })
                Require(PasswordKeyService.AnalyzeUserPassword(invalid).Guessability?.Status == PasswordModelStatus.Skipped,
                    "An empty or syntactically invalid input accessed analysis data.");
            void ExpectGuard(Action action)
            {
                try { action(); throw new InvalidOperationException("Model access unexpectedly escaped the guard."); }
                catch (InvalidOperationException error) when (error.Message.StartsWith("Password supplementary model", StringComparison.Ordinal)) { }
            }
            ExpectGuard(() => PasswordGuessabilityService.Evaluate("Guarded cached model test input!", 200));
            ExpectGuard(() => PasswordModelData.Load());
            await Task.Run(() => ExpectGuard(() => PasswordGuessabilityService.Evaluate("Inherited model guard test input!", 200))).ConfigureAwait(false);
            Require(attempts == 3, "The isolated guard did not observe every attempted Evaluate/Load call.");
            release.SetResult(); await outside.ConfigureAwait(false);
        }
        Require(PasswordGuessabilityService.Evaluate("After isolated guard synthetic input!", 200).Status == PasswordModelStatus.Available,
            "The model guard was not restored after disposal.");
    }

    private static Task TestPasswordModelBoundedAsync()
    {
        _ = PasswordGuessabilityService.Evaluate("Warm model timing synthetic input!", 200);
        foreach (string input in PasswordModelSyntheticCorpus())
        {
            var watch = Stopwatch.StartNew();
            PasswordGuessabilityAnalysis analysis = PasswordGuessabilityService.Evaluate(input, 1000);
            Require(analysis.Status == PasswordModelStatus.Available && double.IsFinite(analysis.CorrectedBits),
                "A bounded synthetic input failed analysis.");
            Require(watch.Elapsed < TimeSpan.FromSeconds(5), "A supported 256-code-unit input exceeded the bounded analysis regression budget.");
        }
        return Task.CompletedTask;
    }

    private static IEnumerable<string> PasswordModelSyntheticCorpus()
    {
        yield return new string('a', 256);
        yield return new string('A', 256);
        yield return new string('1', 256);
        yield return string.Concat(Enumerable.Repeat("Sommer-Wiese_Mond.Vulkan ", 9))
            + "\u200b\u200c\u200d\u2060\ufeff\u00ad\u2063\u2062";
        foreach (string block in new[] { "Sommer", "abcXYZ", "aaaaax", "p@ssw0rd", "1q2w3e4r", "Sommer-Wiese_Mond.Vulkan ", "🦊🛰️🧬" })
        {
            string repeated = string.Concat(Enumerable.Repeat(block, 256 / block.Length));
            yield return repeated;
            yield return repeated[..^(char.IsLowSurrogate(repeated[^1]) ? 2 : 1)] + "!";
        }
        var random = new Random(502);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$%^&*()_-+=?";
        for (int sample = 0; sample < 12; sample++)
            yield return string.Concat(Enumerable.Range(0, 24 + sample * 19).Select(_ => alphabet[random.Next(alphabet.Length)]));
    }

    // Source: https://raw.githubusercontent.com/trezor/python-mnemonic/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json
    // Source SHA256: fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8
    // Public MIT-licensed Trezor vectors and two independent Python-derived
    // 15/21-word vectors. These are public test examples, never user credentials or wallet seeds.
    private static readonly (string EntropyHex, string Mnemonic)[] PasswordModelBip39Vectors = [
        ("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"),
        ("80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"),
        ("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
        ("000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"),
        ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"),
        ("808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"),
        ("0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
        ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
        ("8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
        ("9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"),
        ("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b", "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"),
        ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"),
        ("c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"),
        ("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"),
        ("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"),
        ("23db8160a31d3e0dca3688ed941adbf3", "cat swing flag economy stadium alone churn speed unique patch report train"),
        ("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access"),
        ("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"),
        ("f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture"),
        ("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump"),
        ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"),
        ("000102030405060708090a0b0c0d0e0f10111213", "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math exhibit"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b", "abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch saddle"),
    ];
}
