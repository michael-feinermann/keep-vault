using System.IO;
using System.Linq;

namespace KalynaArchiver.Services;

public enum EncryptionSuite
{
    Kalyna512_512 = 0,
    Threefish1024 = 1,

    /// <summary>XChaCha20-Poly1305 over Threefish-1024, Kalyna-512/512 and AES-256.</summary>
    StandardCascade = 2,

    /// <summary>Eight independently keyed cipher stages with two complete master-KDF rounds.</summary>
    ParanoiaCascade = 3,

    /// <summary>XChaCha20-Poly1305 over AES-256, both hardware-friendly.</summary>
    XChaChaOverAes = 4,

    /// <summary>AES-256 in CTR, alone.</summary>
    Aes256 = 5,

    /// <summary>MARS-448 in CTR, alone.</summary>
    Mars448 = 6,

    /// <summary>SHACAL-2-512 in CTR, alone.</summary>
    Shacal2_512 = 7,

    /// <summary>XChaCha20-Poly1305, alone.</summary>
    XChaCha20Poly1305 = 8,

    /// <summary>XChaCha20-Poly1305(Threefish-1024(AES-256)).</summary>
    MixedCascade = 9,
    Camellia256 = 10,
    Serpent256 = 11,
}

/// <summary>
/// One layer of a cascade: which cipher, and the key and nonce it owns.
/// </summary>
/// <remarks>
/// Cascades are described as an ordered list of these rather than as named
/// inner and outer halves, because one suite has eight layers. The order is
/// the order the plaintext travels: index 0 is applied first and is therefore
/// the innermost, and the last entry is what an attacker meets first.
/// </remarks>
internal sealed record CascadeStage(
    CascadeCipher Cipher,
    int KeyBytes,
    int NonceBytes,
    int BlockBytes);

internal enum CascadeCipher
{
    Aes256,
    Mars448,
    Shacal2_512,
    Kalyna512_512,
    Threefish1024,
    XChaCha20Poly1305,
    Camellia256,
    Serpent256,
}

/// <summary>
/// How a cascade divides its derived key and its nonce between its layers.
/// </summary>
/// <remarks>
/// Written out rather than inferred at the call sites: an off-by-one in this
/// split would hand one layer part of another layer's key and still produce a
/// container that decrypts correctly on the same build, which is exactly the
/// kind of fault that only surfaces years later on a different one.
/// </remarks>
internal sealed record CascadeLayout(IReadOnlyList<CascadeStage> Stages)
{
    public int TotalKeyBytes => Stages.Sum(stage => stage.KeyBytes);

    public int TotalNonceBytes => Stages.Sum(stage => stage.NonceBytes);

    /// <summary>
    /// Whether the outermost layer authenticates as well as encrypts, which
    /// means every chunk carries a tag the container has to store.
    /// </summary>
    public bool OutermostIsAead => Stages[^1].Cipher == CascadeCipher.XChaCha20Poly1305;
}

internal sealed record EncryptionSuiteParameters(
    EncryptionSuite Suite,
    string Algorithm,
    string DisplayName,
    int BlockBytes,
    int StageNonceBytes,
    int EncryptionKeyBytes,
    int Sha3MacKeyBytes,
    int SkeinMacKeyBytes,
    int TweakBytes,
    CascadeLayout? Cascade = null,
    bool UsesTwoKdfRounds = false)
{
    public int ArchiveNonceBytes => EncryptionSuiteCatalog.ArchiveNonceBytes;
    public int SecondArchiveNonceBytes => UsesTwoKdfRounds ? ArchiveNonceBytes : 0;
    public int ChunkNonceBaseBytes => checked(ArchiveNonceBytes + SecondArchiveNonceBytes);
    public int NonceBlockCapacity => ChunkNonceBaseBytes / EncryptionSuiteCatalog.PoolDigestBytes;
    public int ActiveNonceBlockCount
    {
        get
        {
            if (StageNonceBytes <= 0) throw new InvalidDataException("A suite needs a positive stage nonce width.");
            int count = 1 + (StageNonceBytes - 1) / EncryptionSuiteCatalog.PoolDigestBytes;
            if (count > NonceBlockCapacity) throw new InvalidDataException("The registered stage layout exceeds its nonce basis.");
            return count;
        }
    }
    public int ActiveRotatedNonceBytes => checked(EncryptionSuiteCatalog.PoolDigestBytes * ActiveNonceBlockCount);
    public int ReservedNonceBlockCount => NonceBlockCapacity - ActiveNonceBlockCount;
    public int DerivedKeyBytes => checked(EncryptionKeyBytes + Sha3MacKeyBytes + SkeinMacKeyBytes);
}

internal static class EncryptionSuiteCatalog
{
    public const int NoncePoolCount = 5;
    public const int PoolDigestBytes = 64;
    public const int ArchiveNonceBytes = NoncePoolCount * PoolDigestBytes;
    public const string NonceDerivationMode = "Seed320-Blockwise64-SHA3-512-ActivePrefix-v3";
    public const string KalynaAlgorithm = "Kalyna-512/512-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string ThreefishAlgorithm = "Threefish-1024-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string StandardAlgorithm =
        "XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(AES-256-CTR)))"
        + "+HMAC-SHA3-512+Skein-MAC-1024";
    public const string ParanoiaAlgorithm =
        "XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(SHACAL-2-512-CTR("
        + "Serpent-256-CTR(Camellia-256-CTR(MARS-448-CTR(AES-256-CTR)))))))+HMAC-SHA3-512+Skein-MAC-1024";
    public const string FastAlgorithm =
        "XChaCha20-Poly1305(AES-256-CTR)+HMAC-SHA3-512+Skein-MAC-1024";
    public const string Aes256Algorithm = "AES-256-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string Mars448Algorithm = "MARS-448-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string Shacal2Algorithm = "SHACAL-2-512-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string XChaChaAlgorithm = "XChaCha20-Poly1305+HMAC-SHA3-512+Skein-MAC-1024";
    public const string MixedAlgorithm =
        "XChaCha20-Poly1305(Threefish-1024-CTR(AES-256-CTR))+HMAC-SHA3-512+Skein-MAC-1024";
    public const string CamelliaAlgorithm = "Camellia-256-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string SerpentAlgorithm = "Serpent-256-CTR+HMAC-SHA3-512+Skein-MAC-1024";
    public const string CounterEndian = "BigEndian";
    public const string ThreefishTweakMode = "SHA3-512(LP(Domain)||LP(Algorithm)||LE32(StageIndex)||LP(Nonce))[0..15]";

    /// <summary>
    /// The suite offered unless the user chooses otherwise.
    /// </summary>
    public const EncryptionSuite Default = EncryptionSuite.StandardCascade;

    private static readonly EncryptionSuiteParameters Kalyna = new(
        EncryptionSuite.Kalyna512_512,
        KalynaAlgorithm,
        "Kalyna 512/512",
        BlockBytes: 64,
        StageNonceBytes: 64,
        EncryptionKeyBytes: 64,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 0);

    private static readonly EncryptionSuiteParameters Threefish = new(
        EncryptionSuite.Threefish1024,
        ThreefishAlgorithm,
        "Threefish 1024",
        BlockBytes: 128,
        StageNonceBytes: 128,
        EncryptionKeyBytes: 128,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16);

    // The flat buffers store independently derived stage keys and nonce slices.
    // Their order is the inner-to-outer execution order, not a strength estimate.
    private static readonly EncryptionSuiteParameters Standard = new(
        EncryptionSuite.StandardCascade,
        StandardAlgorithm,
        "Standard: XChaCha20-Poly1305 over Threefish-1024, Kalyna-512/512 and AES-256",
        BlockBytes: 128,
        StageNonceBytes: 232,
        EncryptionKeyBytes: 256,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16,
        Cascade: new CascadeLayout([
            new CascadeStage(CascadeCipher.Aes256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Kalyna512_512, KeyBytes: 64, NonceBytes: 64, BlockBytes: 64),
            new CascadeStage(CascadeCipher.Threefish1024, KeyBytes: 128, NonceBytes: 128, BlockBytes: 128),
            new CascadeStage(CascadeCipher.XChaCha20Poly1305, KeyBytes: 32, NonceBytes: 24, BlockBytes: 64),
        ]));

    // Eight independently keyed stages; global AND-MAC and outer chunk AEAD remain mandatory.
    private static readonly EncryptionSuiteParameters Paranoia = new(
        EncryptionSuite.ParanoiaCascade,
        ParanoiaAlgorithm,
        "Paranoia: XChaCha20-Poly1305 over Threefish, Kalyna, SHACAL-2, Serpent, Camellia, MARS and AES",
        // The widest block in the stack; the header reports the composite, and
        // Cascade below is what states each layer's own share.
        BlockBytes: 128,
        StageNonceBytes: 312,
        EncryptionKeyBytes: 440,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16,
        Cascade: new CascadeLayout([
            new CascadeStage(CascadeCipher.Aes256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Mars448, KeyBytes: 56, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Camellia256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Serpent256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Shacal2_512, KeyBytes: 64, NonceBytes: 32, BlockBytes: 32),
            new CascadeStage(CascadeCipher.Kalyna512_512, KeyBytes: 64, NonceBytes: 64, BlockBytes: 64),
            new CascadeStage(CascadeCipher.Threefish1024, KeyBytes: 128, NonceBytes: 128, BlockBytes: 128),
            new CascadeStage(CascadeCipher.XChaCha20Poly1305, KeyBytes: 32, NonceBytes: 24, BlockBytes: 64),
        ]),
        UsesTwoKdfRounds: true);

    /// <summary>
    /// A suite built from exactly one cipher.
    /// </summary>
    /// <remarks>
    /// Declared as a one-stage cascade rather than as a special case, so the
    /// transform, the counter and the AEAD handling all come from the same code
    /// that drives the multi-layer suites. A single cipher is a cascade of
    /// length one; treating it as anything else is how suites end up with their
    /// own quietly divergent paths.
    /// </remarks>
    private static EncryptionSuiteParameters Single(
        EncryptionSuite suite,
        string algorithm,
        string displayName,
        CascadeCipher cipher,
        int keyBytes,
        int nonceBytes,
        int blockBytes)
    {
        return new EncryptionSuiteParameters(
            suite,
            algorithm,
            displayName,
            BlockBytes: blockBytes,
            StageNonceBytes: nonceBytes,
            EncryptionKeyBytes: keyBytes,
            Sha3MacKeyBytes: 64,
            SkeinMacKeyBytes: 128,
            TweakBytes: 0,
            Cascade: new CascadeLayout([
                new CascadeStage(cipher, keyBytes, nonceBytes, blockBytes),
            ]));
    }

    private static readonly EncryptionSuiteParameters Fast = new(
        EncryptionSuite.XChaChaOverAes,
        FastAlgorithm,
        "XChaCha20-Poly1305 over AES-256",
        BlockBytes: 64,
        StageNonceBytes: 40,
        EncryptionKeyBytes: 64,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 0,
        Cascade: new CascadeLayout([
            new CascadeStage(CascadeCipher.Aes256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.XChaCha20Poly1305, KeyBytes: 32, NonceBytes: 24, BlockBytes: 64),
        ]));

    /// <summary>
    /// Three layers, three cipher families, one Argon2id round.
    /// </summary>
    private static readonly EncryptionSuiteParameters Mixed = new(
        EncryptionSuite.MixedCascade,
        MixedAlgorithm,
        "XChaCha20-Poly1305 over Threefish-1024 and AES-256",
        BlockBytes: 128,
        StageNonceBytes: 168,
        EncryptionKeyBytes: 192,
        Sha3MacKeyBytes: 64,
        SkeinMacKeyBytes: 128,
        TweakBytes: 16,
        Cascade: new CascadeLayout([
            new CascadeStage(CascadeCipher.Aes256, KeyBytes: 32, NonceBytes: 16, BlockBytes: 16),
            new CascadeStage(CascadeCipher.Threefish1024, KeyBytes: 128, NonceBytes: 128, BlockBytes: 128),
            new CascadeStage(CascadeCipher.XChaCha20Poly1305, KeyBytes: 32, NonceBytes: 24, BlockBytes: 64),
        ]));

    private static readonly EncryptionSuiteParameters Aes = Single(
        EncryptionSuite.Aes256, Aes256Algorithm, "AES-256",
        CascadeCipher.Aes256, keyBytes: 32, nonceBytes: 16, blockBytes: 16);

    private static readonly EncryptionSuiteParameters Mars = Single(
        EncryptionSuite.Mars448, Mars448Algorithm, "MARS-448",
        CascadeCipher.Mars448, keyBytes: 56, nonceBytes: 16, blockBytes: 16);

    private static readonly EncryptionSuiteParameters Shacal2 = Single(
        EncryptionSuite.Shacal2_512, Shacal2Algorithm, "SHACAL-2-512",
        CascadeCipher.Shacal2_512, keyBytes: 64, nonceBytes: 32, blockBytes: 32);

    private static readonly EncryptionSuiteParameters XChaCha = Single(
        EncryptionSuite.XChaCha20Poly1305, XChaChaAlgorithm, "XChaCha20-Poly1305",
        CascadeCipher.XChaCha20Poly1305, keyBytes: 32, nonceBytes: 24, blockBytes: 64);

    private static readonly EncryptionSuiteParameters Camellia = Single(
        EncryptionSuite.Camellia256, CamelliaAlgorithm, "Camellia-256",
        CascadeCipher.Camellia256, keyBytes: 32, nonceBytes: 16, blockBytes: 16);

    private static readonly EncryptionSuiteParameters Serpent = Single(
        EncryptionSuite.Serpent256, SerpentAlgorithm, "Serpent-256",
        CascadeCipher.Serpent256, keyBytes: 32, nonceBytes: 16, blockBytes: 16);

    public static EncryptionSuiteParameters Get(EncryptionSuite suite)
    {
        return suite switch
        {
            EncryptionSuite.Kalyna512_512 => Kalyna,
            EncryptionSuite.Threefish1024 => Threefish,
            EncryptionSuite.StandardCascade => Standard,
            EncryptionSuite.ParanoiaCascade => Paranoia,
            EncryptionSuite.XChaChaOverAes => Fast,
            EncryptionSuite.MixedCascade => Mixed,
            EncryptionSuite.Aes256 => Aes,
            EncryptionSuite.Mars448 => Mars,
            EncryptionSuite.Shacal2_512 => Shacal2,
            EncryptionSuite.XChaCha20Poly1305 => XChaCha,
            EncryptionSuite.Camellia256 => Camellia,
            EncryptionSuite.Serpent256 => Serpent,
            _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite."),
        };
    }

    public static EncryptionSuiteParameters FromAlgorithm(string? algorithm)
    {
        return algorithm switch
        {
            KalynaAlgorithm => Kalyna,
            ThreefishAlgorithm => Threefish,
            StandardAlgorithm => Standard,
            ParanoiaAlgorithm => Paranoia,
            FastAlgorithm => Fast,
            MixedAlgorithm => Mixed,
            Aes256Algorithm => Aes,
            Mars448Algorithm => Mars,
            Shacal2Algorithm => Shacal2,
            XChaChaAlgorithm => XChaCha,
            CamelliaAlgorithm => Camellia,
            SerpentAlgorithm => Serpent,
            _ => throw new InvalidDataException("Container header specifies an unsupported encryption suite."),
        };
    }

    public static int MaxStageNonceBytes { get; } =
        Enum.GetValues<EncryptionSuite>().Where(IsKnown).Max(suite => Get(suite).StageNonceBytes);

    /// <summary>Stable GUI order, independent from serialized numeric IDs.</summary>
    public static IReadOnlyList<EncryptionSuite> DisplayOrder { get; } =
    [
        EncryptionSuite.StandardCascade,
        EncryptionSuite.XChaChaOverAes,
        EncryptionSuite.MixedCascade,
        EncryptionSuite.ParanoiaCascade,
        EncryptionSuite.Threefish1024,
        EncryptionSuite.Kalyna512_512,
        EncryptionSuite.Shacal2_512,
        EncryptionSuite.Mars448,
        EncryptionSuite.Aes256,
        EncryptionSuite.Camellia256,
        EncryptionSuite.Serpent256,
        EncryptionSuite.XChaCha20Poly1305,
    ];

    /// <summary>
    /// The suite's name as a person reads it, in the app's language.
    /// </summary>
    /// <remarks>
    /// Kept here rather than in either GUI because the printed key sheets need
    /// the same wording. A sheet that names the suite differently from the
    /// window that produced it is a sheet its owner cannot match to an archive
    /// years later.
    ///
    /// The cipher names themselves are proper nouns and stay untranslated; only
    /// the roles around them change language.
    /// </remarks>
    public static string DisplayName(EncryptionSuite suite, bool english)
    {
        // Cascades are written the way the layers actually nest, outermost
        // first, the way VeraCrypt names its own: reading the name tells you
        // what reaches the data last and what touches it first. The single
        // ciphers keep their plain names, since there is nothing to nest.
        string data = english ? "Data" : "Daten";
        return suite switch
        {
            EncryptionSuite.StandardCascade =>
                $"Standard: XChaCha20-Poly1305(Threefish 1024(Kalyna 512/512(AES 256({data}))))",
            EncryptionSuite.ParanoiaCascade =>
                "Paranoia: XChaCha20-Poly1305(Threefish 1024(Kalyna 512/512("
                + $"SHACAL-2 512(Serpent 256(Camellia 256(MARS 448(AES 256({data}))))))))",
            EncryptionSuite.XChaChaOverAes => english
                ? $"Fast: XChaCha20-Poly1305(AES 256({data}))"
                : $"Schnell: XChaCha20-Poly1305(AES 256({data}))",
            EncryptionSuite.MixedCascade => english
                ? $"Mixed: XChaCha20-Poly1305(Threefish 1024(AES 256({data})))"
                : $"Gemischt: XChaCha20-Poly1305(Threefish 1024(AES 256({data})))",
            EncryptionSuite.Threefish1024 => "Threefish 1024",
            EncryptionSuite.Kalyna512_512 => "Kalyna 512/512",
            EncryptionSuite.Shacal2_512 => "SHACAL-2 512",
            EncryptionSuite.Mars448 => "MARS 448",
            EncryptionSuite.Aes256 => "AES 256",
            EncryptionSuite.Camellia256 => "Camellia 256",
            EncryptionSuite.Serpent256 => "Serpent 256",
            EncryptionSuite.XChaCha20Poly1305 => "XChaCha20-Poly1305",
            _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "Unknown encryption suite."),
        };
    }

    /// <summary>Reads a user preference only. Archive readers never call this migration helper.</summary>
    public static EncryptionSuite ParsePreference(string? preference)
    {
        // These text labels occurred in saved GUI preferences before v13.
        // They are not enum aliases and are never accepted as archive algorithms.
        if (string.Equals(preference, "ChaChaOverAes", StringComparison.Ordinal)) return EncryptionSuite.XChaChaOverAes;
        if (string.Equals(preference, "ChaCha20Poly1305", StringComparison.Ordinal)) return EncryptionSuite.XChaCha20Poly1305;
        return Enum.TryParse(preference, out EncryptionSuite suite) && IsKnown(suite) ? suite : Default;
    }

    public static bool IsKnown(EncryptionSuite suite) =>
        suite is EncryptionSuite.Kalyna512_512
            or EncryptionSuite.Threefish1024
            or EncryptionSuite.StandardCascade
            or EncryptionSuite.ParanoiaCascade
            or EncryptionSuite.XChaChaOverAes
            or EncryptionSuite.MixedCascade
            or EncryptionSuite.Aes256
            or EncryptionSuite.Mars448
            or EncryptionSuite.Shacal2_512
            or EncryptionSuite.XChaCha20Poly1305
            or EncryptionSuite.Camellia256
            or EncryptionSuite.Serpent256;
}
