using System.IO;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace KalynaArchiver.Services;

public enum PasswordModelStatus { Skipped, Available, Unavailable }

[Flags]
public enum PasswordPatternReasons
{
    None = 0, WordList = 1, RankedWord = 2, Name = 4, KnownPhrase = 8,
    CaseVariant = 16, LeetVariant = 32, UnicodeVariant = 64, Morphology = 128,
    YearOrDate = 256, KeyboardWalk = 512, Sequence = 1024, Repetition = 2048,
    UnknownRemainder = 4096, Bip39Checksum = 8192, Separator = 16384,
}

/// <summary>No password text, normalized copy, matched word, or KDF material is retained here.</summary>
public sealed record PasswordGuessabilityAnalysis(
    PasswordModelStatus Status,
    string ModelVersion,
    double PreviousConservativeBits,
    double? CompleteModelBits,
    string? ModelFamily,
    PasswordPatternReasons Reasons,
    int UnknownCodepoints,
    bool ExactBlocklistMatch,
    bool Bip39ChecksumValid,
    int? Bip39EntropyBits)
{
    public double CorrectedBits => CompleteModelBits is double value ? Math.Min(PreviousConservativeBits, value) : PreviousConservativeBits;
    public bool IsEmpiricallyCalibrated => false;
    public static PasswordGuessabilityAnalysis Skipped(double previous) => new(
        PasswordModelStatus.Skipped, PasswordModelData.Version, previous, null, null,
        PasswordPatternReasons.None, 0, false, false, null);
}

/// <summary>
/// Offline supplementary attack families for archive creation only. Scores describe bounded
/// enumeration models, not measured guess ranks, sources of randomness, or entropy guarantees.
/// Every contributing path covers the complete input, including transformations and unknown rest.
/// The original UTF-16 string remains untouched and is never returned from this analysis.
/// </summary>
public static class PasswordGuessabilityService
{
    private static readonly Lazy<PasswordModelData> Data = new(() => PasswordModelData.Load(), LazyThreadSafetyMode.ExecutionAndPublication);
    private static readonly AsyncLocal<Action?> ForbiddenEvaluation = new();
    private const double TokenFamilyBits = 3; // Eight explicit grammar families; see resource README.
    private const int ReferenceYear = 2026;
    private static readonly string[] MorphologySuffixes = ["s", "es", "n", "en", "e", "er", "ern", "em", "est", "ste", "sten", "ing", "ed", "ly", "ness", "ment", "ung", "ungen", "heit", "keit", "lich"];
    private static readonly string[] MorphologyPrefixes = ["un", "re", "ge", "be", "ver", "ent", "zer"];
    private static readonly string[] CommonSuffixes = ["!", "?", ".", "!!", "!?", "1!", "12!", "123!", "01!", "007", "@", "#", "$", "%", "*", ":)"];
    private sealed record KeyboardLayout(Dictionary<char, (int X, int Y)> Positions, Dictionary<char, char> Shifted);
    private static readonly KeyboardLayout[] Keyboards =
    [
        Keyboard(["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"],
            ["~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?"]),
        Keyboard(["^1234567890ß´", "qwertzuiopü+", "asdfghjklöä#", "<yxcvbnm,.-"],
            ["°!\"§$%&/()=?`", "QWERTZUIOPÜ*", "ASDFGHJKLÖÄ'", ">YXCVBNM;:_"]),
    ];

    internal static IDisposable ForbidEvaluationForTesting(Action? onAttempt = null)
    {
        Action? previous = ForbiddenEvaluation.Value;
        ForbiddenEvaluation.Value = () =>
        {
            onAttempt?.Invoke();
            throw new InvalidOperationException("Password supplementary model evaluation is forbidden in this test scope.");
        };
        return new EvaluationScope(previous);
    }

    private sealed class EvaluationScope(Action? previous) : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            if (disposed) return;
            ForbiddenEvaluation.Value = previous;
            disposed = true;
        }
    }

    internal static void AssertModelAccessAllowedForTesting() => ForbiddenEvaluation.Value?.Invoke();

    public static PasswordGuessabilityAnalysis Evaluate(string password, double previousConservativeBits)
        => EvaluateUsingLoader(password, previousConservativeBits, () => Data.Value);

    internal static PasswordGuessabilityAnalysis EvaluateWithResourcesForTesting(string password, double previousConservativeBits, Func<string, Stream?> resourceReader)
        => EvaluateUsingLoader(password, previousConservativeBits, () => PasswordModelData.Load(resourceReader));

    private static PasswordGuessabilityAnalysis EvaluateUsingLoader(string password, double previousConservativeBits, Func<PasswordModelData> load)
    {
        // Deliberately outside error handling, even when data was loaded by an earlier caller.
        AssertModelAccessAllowedForTesting();
        ArgumentNullException.ThrowIfNull(password);
        if (!double.IsFinite(previousConservativeBits) || previousConservativeBits < 0)
            throw new ArgumentOutOfRangeException(nameof(previousConservativeBits));
        if (password.Length > PasswordKeyService.MaxPasswordLength || password.Length == 0)
            throw new ArgumentOutOfRangeException(nameof(password));
        PasswordModelData model;
        try { model = load(); }
        catch (Exception failure) when (failure is IOException or InvalidDataException or FormatException
            or System.Text.Json.JsonException or DecoderFallbackException or InvalidOperationException
            or KeyNotFoundException or ArgumentException or UnauthorizedAccessException)
        {
            return new(PasswordModelStatus.Unavailable, PasswordModelData.Version, previousConservativeBits,
                null, null, PasswordPatternReasons.None, 0, false, false, null);
        }
        return EvaluateWithData(password, previousConservativeBits, model);
    }

    internal static PasswordGuessabilityAnalysis EvaluateWithData(string password, double previous, PasswordModelData model)
        => EvaluateData(password, previous, model, allowFormatVariant: true);

    private static PasswordGuessabilityAnalysis EvaluateData(string password, double previous, PasswordModelData model, bool allowFormatVariant)
    {
        AssertModelAccessAllowedForTesting();
        string normalized = password.Normalize(NormalizationForm.FormC);
        double unicodeBits = CanonicalVariantBits(password, normalized);
        // Only the explicitly encoded NFC/NFD-per-grapheme family may use the normalized path.
        // Other combining-mark orders are analyzed in their original representation.
        if (double.IsPositiveInfinity(unicodeBits)) { normalized = password; unicodeBits = 0; }
        string lower = normalized.ToLowerInvariant();
        bool nfcChanged = normalized != password;
        List<Edge>[] graph = CreateMatchGraph(normalized, model, allowRepeat: true);
        Candidate? best = Segment(normalized, model, allowRepeat: true, graph: graph);
        char[] separators = new[] { '\0', ' ', '-', '_', '.' }.Where(separator => separator == '\0' || normalized.Contains(separator)).ToArray();
        foreach (char separator in separators)
        {
            foreach (int caseFormat in new[] { 0, 1, 2 })
            {
                if (separator == '\0' && caseFormat == 0) continue;
                if (caseFormat != 0 && !normalized.Any(char.IsUpper)) continue;
                Candidate? formatted = Segment(normalized, model, allowRepeat: true, separator, caseFormat, graph);
                if (formatted is not null)
                    best = Cheaper(best, formatted with { Bits = formatted.Bits + (separator == '\0' ? 0 : 2) + (caseFormat == 0 ? 0 : 2), Family = "complete-fixed-format-grammar" });
            }
        }
        if (best is not null && nfcChanged)
            best = best with { Bits = best.Bits + unicodeBits, Reasons = best.Reasons | PasswordPatternReasons.UnicodeVariant };

        foreach ((string name, string[] words) in model.Lists)
        {
            Candidate? list = FixedWordList(normalized, name, words, model.ListSets[name]);
            if (list is not null && nfcChanged)
                list = list with { Bits = list.Bits + unicodeBits, Reasons = list.Reasons | PasswordPatternReasons.UnicodeVariant };
            best = Cheaper(best, list);
        }
        (bool validChecksum, int? entropyBits) = CheckBip39(lower, model);
        if (validChecksum && entropyBits is int entropy)
        {
            string[] tokens = normalized.Split(' ');
            double variants = tokens.Sum(CaseBits);
            if (tokens.All(token => (GlobalCaseFormats(token) & 1) != 0) || tokens.All(token => (GlobalCaseFormats(token) & 2) != 0)) variants = Math.Min(variants, 2);
            variants += unicodeBits;
            best = Cheaper(best, new Candidate(entropy + variants, "bip39-valid-checksum",
                PasswordPatternReasons.WordList | PasswordPatternReasons.Bip39Checksum
                | (variants > 0 ? PasswordPatternReasons.CaseVariant : PasswordPatternReasons.None), 0));
        }
        // A checksum-valid sequence is also recognized in fixed separators, concatenations and
        // leet forms. Component edges remain available to the complete DAG when a prefix or
        // suffix follows; their entropy cap never discards that remaining input.
        foreach (Edge edge in graph[0].Where(edge => edge.End == normalized.Length && edge.Bip39Entropy is not null))
        {
            double cases = edge.CaseFormats > 0 ? Math.Min(edge.CaseCost, 2) : edge.CaseCost;
            best = Cheaper(best, new Candidate(edge.Bits - edge.CaseCost + cases + unicodeBits,
                "bip39-checksum-with-format", edge.Reasons, 0));
            validChecksum = true;
            entropyBits = entropyBits is int prior ? Math.Min(prior, edge.Bip39Entropy!.Value) : edge.Bip39Entropy;
        }
        if (allowFormatVariant)
        {
            foreach (var format in UniformFormatVariants(password))
            {
                PasswordGuessabilityAnalysis baseValue = EvaluateData(format.Text, previous, model, allowFormatVariant: false);
                if (baseValue.CompleteModelBits is double baseBits)
                    best = Cheaper(best, new Candidate(baseBits + format.Bits, "complete-periodic-format-variant",
                        baseValue.Reasons | PasswordPatternReasons.UnicodeVariant, baseValue.UnknownCodepoints));
            }
        }
        // Exact original whole-input match. The distributed source corpus consists of lowercase
        // candidates; capitalization and other variants are analyzed separately, not called leaks.
        bool blocked = model.Blocklist.Contains(password);
        return new(PasswordModelStatus.Available, PasswordModelData.Version, previous,
            best?.Bits, best?.Family, best?.Reasons ?? PasswordPatternReasons.None,
            best?.Unknown ?? password.EnumerateRunes().Count(), blocked, validChecksum, entropyBits);
    }

    private static IEnumerable<(string Text, double Bits)> UniformFormatVariants(string original)
    {
        // Eight explicitly enumerated analysis-only format scalars. Other characters remain in
        // the base, including other format characters. Never strip arbitrary Cf positions.
        int[] alphabet = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x2063, 0x2062];
        // Every applicable alphabet member is a competing complete strategy. Encounter order
        // must not hide a cheaper strategy for a later format character.
        foreach (int selected in alphabet)
        {
            if (!original.Contains((char)selected)) continue; // This fixed alphabet is entirely BMP.
            var clean = new StringBuilder(); var positions = new List<int>(); int length = 0;
            foreach (Rune rune in original.EnumerateRunes())
            {
                if (rune.Value == selected) positions.Add(length);
                else { clean.Append(rune.ToString()); length++; }
            }
            if (length == 0 || positions.Count == 0) continue;
            double? bits = positions.Count == 1 ? Math.Log2(alphabet.Length * (length + 1.0)) : null;
            for (int period = 1; period <= length; period++)
            {
                bool afterBetween = positions.SequenceEqual(Enumerable.Range(1, (length - 1) / period).Select(index => index * period));
                bool afterIncludingEnd = positions.SequenceEqual(Enumerable.Range(1, length / period).Select(index => index * period));
                bool beforeGroups = positions.SequenceEqual(Enumerable.Range(0, (length - 1) / period + 1).Select(index => index * period));
                if (!afterBetween && !afterIncludingEnd && !beforeGroups) continue;
                // Enumeration through the observed positive period, all eight scalars, three exact
                // placement/end modes. This describes every removed scalar and its full position.
                double cost = Math.Log2(alphabet.Length * 3.0 * period);
                bits = bits is double current ? Math.Min(current, cost) : cost;
            }
            if (bits is double result) yield return (clean.ToString(), result);
        }
    }

    private sealed record Candidate(double Bits, string Family, PasswordPatternReasons Reasons, int Unknown);
    private sealed record Edge(int End, double Bits, PasswordPatternReasons Reasons, double CaseCost = 0, int CaseFormats = -1, int? Bip39Entropy = null);

    private static Candidate? Cheaper(Candidate? first, Candidate? second) =>
        second is not null && (first is null || second.Bits < first.Bits) ? second : first;

    private static Candidate? FixedWordList(string password, string name, string[] entries, HashSet<string> words)
    {
        Candidate? best = null;
        // Each model conditions on one fixed representation; separators are not random choices.
        foreach (char separator in new[] { ' ', '-', '_', '.' })
        {
            string[] tokens = password.Split(separator);
            if (tokens.Length < 2 || tokens.Any(token => token.Length == 0 || !words.Contains(token.ToLowerInvariant()))) continue;
            double variants = tokens.Sum(CaseBits);
            if (tokens.All(token => (GlobalCaseFormats(token) & 1) != 0) || tokens.All(token => (GlobalCaseFormats(token) & 2) != 0)) variants = Math.Min(variants, 2);
            best = Cheaper(best, new Candidate(tokens.Length * Math.Log2(entries.Length) + variants,
                name + ":fixed-separator", PasswordPatternReasons.WordList | PasswordPatternReasons.Separator
                | (variants > 0 ? PasswordPatternReasons.CaseVariant : PasswordPatternReasons.None), 0));
        }
        // All segmentations, including uniform title-case / uppercase. k is not inferred from capitals.
        foreach (int caseFormat in new[] { 0, 1, 2 })
        {
            double[] costs = Enumerable.Repeat(double.PositiveInfinity, password.Length + 1).ToArray();
            int[] counts = new int[costs.Length]; costs[0] = 0;
            int maxLength = entries.Max(static word => word.Length);
            for (int start = 0; start < password.Length; start++)
            {
                if (double.IsPositiveInfinity(costs[start])) continue;
                for (int end = start + 1; end <= Math.Min(password.Length, start + maxLength); end++)
                {
                    string token = password[start..end];
                    if (!words.Contains(token.ToLowerInvariant()) || caseFormat != 0 && (GlobalCaseFormats(token) & caseFormat) == 0) continue;
                    double cost = costs[start] + Math.Log2(entries.Length) + (caseFormat == 0 ? CaseBits(token) : 0);
                    if (cost < costs[end]) { costs[end] = cost; counts[end] = counts[start] + 1; }
                }
            }
            if (counts[^1] >= 2)
                best = Cheaper(best, new Candidate(costs[^1] + (caseFormat == 0 ? 0 : 2), name + ":concatenated", PasswordPatternReasons.WordList | (caseFormat == 0 ? 0 : PasswordPatternReasons.CaseVariant), 0));
        }
        return best;
    }

    private static List<Edge>[] CreateMatchGraph(string text, PasswordModelData model, bool allowRepeat)
    {
        string lower = text.ToLowerInvariant();
        var graph = new List<Edge>[text.Length];
        List<Bip39Word>[]? bip39Words = text.Length >= 36 ? MatchBip39Words(text, lower, model) : null;
        for (int start = 0; start < text.Length; start++)
        {
            if (char.IsLowSurrogate(text[start])) { graph[start] = []; continue; }
            graph[start] = MatchWords(text, lower, start, model);
            MatchSimplePatterns(text, lower, start, graph[start]);
            if (bip39Words is not null && text.Length - start >= 36)
                MatchBip39Components(text, start, bip39Words, graph[start]);
            if (allowRepeat) MatchRepeats(text, start, model, graph[start]);
        }
        return graph;
    }

    private sealed record Bip39Word(int End, int Index, double LeetCost, double CaseCost, int CaseFormats);
    private sealed record Bip39Path(int Position, int[] Indices, double Variants, double Cases, int CaseFormats, char? Separator);

    private static List<Bip39Word>[] MatchBip39Words(string text, string lower, PasswordModelData model)
    {
        var result = new List<Bip39Word>[text.Length];
        for (int start = 0; start < text.Length; start++)
        {
            result[start] = [];
            var states = new List<(PasswordModelData.TrieNode Node, double Bits)> { (model.Bip39Root, 0) };
            for (int end = start; end < Math.Min(text.Length, start + 8) && states.Count > 0; end++)
            {
                var next = new List<(PasswordModelData.TrieNode Node, double Bits)>();
                string alternatives = LeetAlternatives(lower[end]);
                foreach ((PasswordModelData.TrieNode node, double bits) in states)
                    foreach (char character in alternatives)
                        if (node.Children.TryGetValue(character, out PasswordModelData.TrieNode? child))
                        {
                            double cost = bits + (character == lower[end] ? 0 : Math.Log2(alternatives.Length));
                            next.Add((child, cost));
                            if (child.Bip39Index is int index)
                            {
                                string token = text[start..(end + 1)];
                                result[start].Add(new Bip39Word(end + 1, index, cost, CaseBits(token), GlobalCaseFormats(token)));
                            }
                        }
                states = next.OrderBy(static node => node.Bits).Take(128).ToList();
            }
        }
        return result;
    }

    private static void MatchBip39Components(string text, int start, List<Bip39Word>[] words, List<Edge> result)
    {
        var pending = new Queue<Bip39Path>();
        pending.Enqueue(new Bip39Path(start, [], 0, 0, 3, null));
        int examined = 0;
        // Bounded ambiguity exploration. Omitted hypotheses are neutral, never a strength claim.
        try
        {
            while (pending.Count > 0 && examined++ < 4096)
            {
                Bip39Path path = pending.Dequeue();
                try
                {
                    foreach (Bip39Word word in words[path.Position])
                    {
                        int[] indices = [.. path.Indices, word.Index];
                        bool queued = false;
                        try
                        {
                            double variants = path.Variants + word.LeetCost;
                            double cases = path.Cases + word.CaseCost;
                            int formats = path.CaseFormats & word.CaseFormats;
                            char separator = path.Separator ?? (word.End < text.Length && text[word.End] is ' ' or '-' or '_' or '.' ? text[word.End] : '\0');
                            if (indices.Length is 12 or 15 or 18 or 21 or 24 && CheckBip39Indices(indices) is int entropy)
                            {
                                double representation = separator == ' ' ? 0 : 3; // Eight declared representation slots.
                                PasswordPatternReasons reason = PasswordPatternReasons.WordList | PasswordPatternReasons.Bip39Checksum
                                    | (variants > 0 ? PasswordPatternReasons.LeetVariant : 0)
                                    | (cases > 0 ? PasswordPatternReasons.CaseVariant : 0)
                                    | (separator != '\0' ? PasswordPatternReasons.Separator : 0);
                                result.Add(new Edge(word.End, entropy + variants + cases + representation, reason, cases, formats, entropy));
                            }
                            if (indices.Length >= 24 || word.End >= text.Length) continue;
                            int next = word.End;
                            if (separator != '\0')
                            {
                                if (text[next] != separator || ++next >= text.Length) continue;
                            }
                            if (pending.Count < 4096)
                            {
                                pending.Enqueue(new Bip39Path(next, indices, variants, cases, formats, separator));
                                queued = true;
                            }
                        }
                        finally { if (!queued) Array.Clear(indices); }
                    }
                }
                finally { Array.Clear(path.Indices); }
            }
        }
        finally { foreach (Bip39Path path in pending) Array.Clear(path.Indices); }
    }

    private static Candidate? Segment(string text, PasswordModelData model, bool allowRepeat, char fixedSeparator = '\0', int caseFormat = 0, List<Edge>[]? graph = null)
    {
        int n = text.Length;
        var boundaries = new bool[n + 1]; boundaries[0] = true;
        var rawBits = new double[n + 1]; var runeCounts = new int[n + 1];
        int offset = 0;
        foreach (Rune rune in text.EnumerateRunes())
        {
            int next = offset + rune.Utf16SequenceLength;
            // Explicit scalar enumeration, never two independent surrogate characters.
            rawBits[next] = rawBits[offset] + Math.Log2(rune.IsAscii ? 95 : 0x110000 - 0x800);
            runeCounts[next] = runeCounts[offset] + 1; boundaries[next] = true; offset = next;
        }
        var best = new Candidate?[n + 1, 2];
        best[0, 0] = new Candidate(0, "complete-segmentation", PasswordPatternReasons.None, 0);
        graph ??= CreateMatchGraph(text, model, allowRepeat);
        for (int start = 0; start < n; start++)
        {
            if (!boundaries[start]) continue;
            List<Edge> matches = graph[start];
            if (caseFormat != 0)
                matches = matches.Where(edge => edge.CaseFormats == -1 || (edge.CaseFormats & caseFormat) != 0)
                    .Select(edge => edge with { Bits = edge.Bits - edge.CaseCost }).ToList();
            if (fixedSeparator != '\0')
            {
                matches = [.. matches];
                foreach (Edge edge in matches.ToArray())
                    if (edge.End < n && text[edge.End] == fixedSeparator && (edge.Reasons & PasswordPatternReasons.Separator) == 0)
                        matches.Add(edge with { End = edge.End + 1, Reasons = edge.Reasons | PasswordPatternReasons.Separator });
            }
            for (int kind = 0; kind <= 1; kind++)
            {
                Candidate? prefix = best[start, kind];
                if (prefix is null) continue;
                foreach (Edge edge in matches)
                {
                    if (!boundaries[edge.End]) continue;
                    var candidate = new Candidate(prefix.Bits + TokenFamilyBits + edge.Bits,
                        "complete-segmentation", prefix.Reasons | edge.Reasons, prefix.Unknown);
                    best[edge.End, 1] = Cheaper(best[edge.End, 1], candidate);
                }
                for (int end = start + 1; end <= n; end++)
                {
                    if (!boundaries[end]) continue;
                    double lengthBits = Math.Log2(PasswordKeyService.MaxPasswordLength);
                    var candidate = new Candidate(prefix.Bits + TokenFamilyBits + lengthBits + rawBits[end] - rawBits[start],
                        "complete-segmentation", prefix.Reasons | PasswordPatternReasons.UnknownRemainder,
                        prefix.Unknown + runeCounts[end] - runeCounts[start]);
                    best[end, kind] = Cheaper(best[end, kind], candidate);
                }
            }
        }
        return best[n, 1];
    }

    private static List<Edge> MatchWords(string text, string lower, int start, PasswordModelData model)
    {
        var edges = new List<Edge>();
        var states = new List<(PasswordModelData.TrieNode Node, double Leet)> { (model.Root, 0) };
        for (int end = start; end < Math.Min(text.Length, start + model.MaximumWordLength) && states.Count > 0; end++)
        {
            var next = new Dictionary<PasswordModelData.TrieNode, double>();
            string alternatives = LeetAlternatives(lower[end]);
            foreach ((PasswordModelData.TrieNode node, double leet) in states)
                foreach (char character in alternatives)
                {
                    if (!node.Children.TryGetValue(character, out PasswordModelData.TrieNode? child)) continue;
                    double cost = leet + (character == lower[end] ? 0 : Math.Log2(alternatives.Length));
                    if (!next.TryGetValue(child, out double old) || cost < old) next[child] = cost;
                }
            // Ambiguous leet recognition is bounded. Dropped paths are neutral; they never improve a score.
            states = next.OrderBy(static item => item.Value).Take(128).Select(static item => (item.Key, item.Value)).ToList();
            foreach ((PasswordModelData.TrieNode node, double leet) in states)
            {
                if (node.Word is not PasswordModelData.Word word || end - start + 1 < 3) continue;
                string token = text[start..(end + 1)];
                double casing = CaseBits(token);
                var reason = word.Reason | (casing > 0 ? PasswordPatternReasons.CaseVariant : 0)
                    | (leet > 0 ? PasswordPatternReasons.LeetVariant : 0);
                edges.Add(new Edge(end + 1, word.Bits + casing + leet, reason, casing, GlobalCaseFormats(token)));
            }
        }
        // Finite morphology, not a linguistic completeness claim. Compounds use the segmentation DAG.
        for (int end = start + 4; end <= Math.Min(text.Length, start + 40); end++)
        {
            string token = lower[start..end];
            foreach (string suffix in MorphologySuffixes)
                if (token.EndsWith(suffix, StringComparison.Ordinal) && token.Length - suffix.Length >= 3
                    && MorphologicalRoot(model, token[..^suffix.Length]) is PasswordModelData.Word root)
                    edges.Add(new Edge(end, root.Bits + Math.Log2((MorphologySuffixes.Length + MorphologyPrefixes.Length) * 4) + CaseBits(text[start..end]), root.Reason | PasswordPatternReasons.Morphology, CaseBits(text[start..end]), GlobalCaseFormats(text[start..end])));
            foreach (string prefix in MorphologyPrefixes)
                if (token.StartsWith(prefix, StringComparison.Ordinal) && token.Length - prefix.Length >= 3
                    && MorphologicalRoot(model, token[prefix.Length..]) is PasswordModelData.Word root)
                    edges.Add(new Edge(end, root.Bits + Math.Log2((MorphologySuffixes.Length + MorphologyPrefixes.Length) * 4) + CaseBits(text[start..end]), root.Reason | PasswordPatternReasons.Morphology, CaseBits(text[start..end]), GlobalCaseFormats(text[start..end])));
        }
        return edges;
    }

    private static PasswordModelData.Word? MorphologicalRoot(PasswordModelData model, string stem)
    {
        string[] forms = [stem, stem + "e", stem.Length > 3 && stem[^1] == stem[^2] ? stem[..^1] : stem,
            stem.Replace('ä', 'a').Replace('ö', 'o').Replace('ü', 'u')];
        PasswordModelData.Word? best = null;
        foreach (string form in forms)
            if (model.Words.TryGetValue(form, out PasswordModelData.Word? word) && (best is null || word.Bits < best.Bits)) best = word;
        return best;
    }

    private static string LeetAlternatives(char value) => value switch
    {
        '0' => "0o", '1' => "1il", '3' => "3e", '4' => "4a", '@' => "@a",
        '$' => "$s", '5' => "5s", '7' => "7t", '+' => "+t", '8' => "8b", '9' => "9g",
        _ => value.ToString(),
    };

    private static double CaseBits(string text)
    {
        if (text == text.ToLowerInvariant()) return 0;
        if (text == text.ToUpperInvariant()) return 1;
        int firstLetter = -1;
        for (int i = 0; i < text.Length; i++) if (char.IsLetter(text[i])) { firstLetter = i; break; }
        if (firstLetter >= 0 && char.IsUpper(text[firstLetter]) && text[(firstLetter + 1)..] == text[(firstLetter + 1)..].ToLowerInvariant()) return 1;
        return text.EnumerateRunes().Count(static rune => Rune.IsLetter(rune));
    }

    private static int GlobalCaseFormats(string token)
    {
        int result = token == token.ToUpperInvariant() ? 1 : 0;
        bool title = token.Split([' ', '-', '_', '.']).All(part =>
        {
            int first = -1;
            for (int index = 0; index < part.Length; index++)
                if (char.IsLetter(part[index]) || LeetAlternatives(part[index]).Any(char.IsLetter)) { first = index; break; }
            bool possibleUpper = first >= 0 && (char.IsUpper(part[first])
                || !char.IsLetter(part[first]) && LeetAlternatives(part[first]).Any(char.IsLetter));
            return first < 0 || possibleUpper && part[(first + 1)..] == part[(first + 1)..].ToLowerInvariant();
        });
        return result | (title ? 2 : 0);
    }

    private static double CanonicalVariantBits(string original, string normalized)
    {
        if (original == normalized) return 0;
        TextElementEnumerator raw = StringInfo.GetTextElementEnumerator(original);
        TextElementEnumerator nfc = StringInfo.GetTextElementEnumerator(normalized);
        int choices = 0;
        while (nfc.MoveNext())
        {
            if (!raw.MoveNext()) return double.PositiveInfinity;
            string canonical = nfc.GetTextElement();
            string decomposed = canonical.Normalize(NormalizationForm.FormD);
            string actual = raw.GetTextElement();
            if (actual != canonical && actual != decomposed) return double.PositiveInfinity;
            if (canonical != decomposed) choices++;
        }
        return raw.MoveNext() ? double.PositiveInfinity : 1 + choices;
    }

    private static void MatchSimplePatterns(string text, string lower, int start, List<Edge> matches)
    {
        if (text[start] is ' ' or '-' or '_' or '.')
            matches.Add(new Edge(start + 1, 2, PasswordPatternReasons.Separator));
        foreach (string suffix in CommonSuffixes)
            if (text.AsSpan(start).StartsWith(suffix, StringComparison.Ordinal))
                matches.Add(new Edge(start + suffix.Length, Math.Log2(CommonSuffixes.Length), PasswordPatternReasons.Sequence));
        for (int end = start + 3; end <= Math.Min(text.Length, start + 32); end++)
        {
            string part = lower[start..end];
            if (IsSequence(part)) matches.Add(new Edge(end, 7 + 1 + Math.Log2(256) + CaseBits(text[start..end]), PasswordPatternReasons.Sequence));
            double? keyboard = KeyboardBits(text[start..end]);
            if (keyboard is double bits) matches.Add(new Edge(end, bits, PasswordPatternReasons.KeyboardWalk));
            if (part.Length == 4 && int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out int year) && year is >= 1900 and <= ReferenceYear + 30)
                matches.Add(new Edge(end, Math.Log2(ReferenceYear + 30 - 1900 + 1), PasswordPatternReasons.YearOrDate));
            if (part.Length is 6 or 8 or 10 && IsDate(part))
                matches.Add(new Edge(end, Math.Log2((ReferenceYear + 30 - 1900 + 1) * 366.0 * 6 * 4), PasswordPatternReasons.YearOrDate));
        }
    }

    private static bool IsSequence(string text)
    {
        if (text.Length < 3 || text.Any(static c => !char.IsAsciiLetterOrDigit(c))) return false;
        int step = text[1] - text[0];
        return step is 1 or -1 && Enumerable.Range(2, text.Length - 2).All(index => text[index] - text[index - 1] == step);
    }

    private static bool IsDate(string text)
    {
        string compact = text.Replace(".", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal).Replace("/", string.Empty, StringComparison.Ordinal);
        if (compact.Length is not (6 or 8) || !compact.All(char.IsAsciiDigit)) return false;
        if (compact.Length != text.Length)
        {
            bool dayFirst = text.Length is 8 or 10 && text[2] is '.' or '-' or '/' && text[5] == text[2];
            bool yearFirst = text.Length == 10 && text[4] is '.' or '-' or '/' && text[7] == text[4];
            if (!dayFirst && !yearFirst || text.Length - compact.Length != 2) return false;
        }
        int Read(int start, int length) => int.Parse(compact.AsSpan(start, length), NumberStyles.None, CultureInfo.InvariantCulture);
        bool Valid(int day, int month, int year) => year is >= 1900 and <= ReferenceYear + 30
            && month is >= 1 and <= 12 && day >= 1 && day <= DateTime.DaysInMonth(year, month);
        if (compact.Length == 8)
            return Valid(Read(0, 2), Read(2, 2), Read(4, 4))
                || Valid(Read(2, 2), Read(0, 2), Read(4, 4))
                || Valid(Read(6, 2), Read(4, 2), Read(0, 4));
        foreach (int century in new[] { 1900, 2000 })
        {
            if (Valid(Read(0, 2), Read(2, 2), century + Read(4, 2))
                || Valid(Read(2, 2), Read(0, 2), century + Read(4, 2))
                || Valid(Read(4, 2), Read(2, 2), century + Read(0, 2))) return true;
        }
        return false;
    }

    private static KeyboardLayout Keyboard(string[] rows, string[] shiftedRows)
    {
        var result = new Dictionary<char, (int, int)>();
        var shifted = new Dictionary<char, char>();
        for (int y = 0; y < rows.Length; y++)
        {
            if (rows[y].Length != shiftedRows[y].Length) throw new InvalidOperationException("Inconsistent keyboard model.");
            for (int x = 0; x < rows[y].Length; x++)
            {
                int leadingKey = y == 0 || rows[y][0] == '<' ? 1 : 0;
                result[rows[y][x]] = (x - leadingKey, y);
                shifted[shiftedRows[y][x]] = rows[y][x];
            }
        }
        return new KeyboardLayout(result, shifted);
    }

    private static double? KeyboardBits(string text)
    {
        double? best = null;
        foreach (KeyboardLayout layout in Keyboards)
        {
            Dictionary<char, (int X, int Y)> keyboard = layout.Positions;
            char Base(char character) => layout.Shifted.TryGetValue(character, out char value) ? value : character;
            if (!keyboard.TryGetValue(Base(text[0]), out var previous)) continue;
            (int, int) lastDirection = (0, 0); int turns = 0; bool walk = true;
            for (int index = 1; index < text.Length; index++)
            {
                if (!keyboard.TryGetValue(Base(text[index]), out var current)) { walk = false; break; }
                var direction = (current.X - previous.X, current.Y - previous.Y);
                if (Math.Abs(direction.Item1) > 1 || Math.Abs(direction.Item2) > 1 || direction == (0, 0)) { walk = false; break; }
                if (index > 1 && direction != lastDirection) turns++;
                lastDirection = direction; previous = current;
            }
            if (!walk) continue;
            int shiftedCount = text.Count(layout.Shifted.ContainsKey);
            double shiftBits = shiftedCount == 0 ? 0 : shiftedCount == text.Length ? 1 : text.Length + 1;
            // Start key, direction, length, turn count, turn positions, changed directions and
            // physical Shift choices. Binomial positions avoid charging every straight run as
            // an independent 256-character length while still covering every ordered walk.
            double bits = Math.Log2(keyboard.Count * 8.0 * 256 * (text.Length - 1))
                + Log2Binomial(text.Length - 2, turns) + turns * Math.Log2(7) + shiftBits;
            best = best is double old ? Math.Min(old, bits) : bits;
        }
        return best;
    }

    private static double Log2Binomial(int n, int selected)
    {
        int count = Math.Min(selected, n - selected);
        double result = 0;
        for (int index = 1; index <= count; index++) result += Math.Log2(n - index + 1) - Math.Log2(index);
        return result;
    }

    private static void MatchRepeats(string text, int start, PasswordModelData model, List<Edge> matches)
    {
        var primitivePeriods = new List<int>();
        for (int period = 1; period <= (text.Length - start) / 2; period++)
        {
            if (primitivePeriods.Any(primitive => period % primitive == 0
                && Enumerable.Range(primitive, period - primitive).All(index => text[start + index] == text[start + index % primitive]))) continue;
            if (char.IsLowSurrogate(text[start + period])) continue;
            string unit = text.Substring(start, period);
            int count = 1;
            while (start + (count + 1) * period <= text.Length && text.AsSpan(start + count * period, period).SequenceEqual(unit)) count++;
            if (count < 2) continue;
            primitivePeriods.Add(period);
            double unitBits = unit.EnumerateRunes().Sum(static rune => Math.Log2(rune.IsAscii ? 95 : 0x110000 - 0x800));
            Candidate? modelled = Segment(unit, model, allowRepeat: false);
            if (modelled is not null) unitBits = Math.Min(unitBits, modelled.Bits);
            for (int repetitions = 2; repetitions <= count; repetitions++)
                matches.Add(new Edge(start + repetitions * period, unitBits + 2 * Math.Log2(256), PasswordPatternReasons.Repetition));
        }
    }

    private static (bool Valid, int? EntropyBits) CheckBip39(string text, PasswordModelData model)
    {
        string[] words = text.Split(' ');
        if (words.Length is not (12 or 15 or 18 or 21 or 24) || words.Any(word => !model.Bip39Indices.ContainsKey(word))) return (false, null);
        int[] indices = words.Select(word => model.Bip39Indices[word]).ToArray();
        try
        {
            int? entropy = CheckBip39Indices(indices);
            return (entropy is not null, entropy);
        }
        finally { Array.Clear(indices); }
    }

    private static int? CheckBip39Indices(int[] indices)
    {
        int entropyBits = indices.Length * 11 * 32 / 33;
        int checksumBits = entropyBits / 32;
        Span<byte> packed = stackalloc byte[33]; packed.Clear();
        Span<byte> digest = stackalloc byte[32];
        try
        {
            int position = 0;
            foreach (int value in indices)
            {
                for (int bit = 10; bit >= 0; bit--, position++)
                    packed[position / 8] |= (byte)(((value >> bit) & 1) << (7 - position % 8));
            }
            SHA256.HashData(packed[..(entropyBits / 8)], digest);
            int actual = packed[entropyBits / 8] >> (8 - checksumBits);
            return actual == digest[0] >> (8 - checksumBits) ? entropyBits : null;
        }
        finally { CryptographicOperations.ZeroMemory(packed); CryptographicOperations.ZeroMemory(digest); }
    }
}
