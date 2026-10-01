using System.IO;
using System.IO.IsolatedStorage;
using System.Security;
using System.Text;

namespace KalynaArchiver.Services;

internal interface IAppSettingsStore
{
    string? Read(string key);

    void Write(string key, string value);
}

internal sealed class IsolatedStorageAppSettingsStore : IAppSettingsStore
{
    internal const int MaxValueBytes = 64;
    internal const string ResourcePreferencesKey = "resources-v13-rev11";
    private static int ValueLimit(string key) => key == ResourcePreferencesKey ? 8192 : MaxValueBytes;
    private const int MaxKeyCharacters = 64;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public string? Read(string key)
    {
        ValidateKey(key);
        try
        {
            using IsolatedStorageFile store = IsolatedStorageFile.GetUserStoreForAssembly();
            if (!store.FileExists(key))
            {
                return null;
            }

            using var stream = new IsolatedStorageFileStream(key, FileMode.Open, FileAccess.Read, FileShare.Read, store);
            if (stream.Length <= 0 || stream.Length > ValueLimit(key))
            {
                return null;
            }

            byte[] encoded = new byte[(int)stream.Length];
            stream.ReadExactly(encoded);
            return DecodeValue(encoded, ValueLimit(key));
        }
        catch (IOException)
        {
            return null;
        }
        catch (IsolatedStorageException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (SecurityException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    public void Write(string key, string value)
    {
        ValidateKey(key);
        ArgumentNullException.ThrowIfNull(value);
        byte[] encoded = StrictUtf8.GetBytes(value);
        if (encoded.Length <= 0 || encoded.Length > ValueLimit(key))
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"A setting value must contain 1 to {ValueLimit(key)} UTF-8 bytes.");
        }

        try
        {
            using IsolatedStorageFile store = IsolatedStorageFile.GetUserStoreForAssembly();
            using var stream = new IsolatedStorageFileStream(key, FileMode.Create, FileAccess.Write, FileShare.None, store);
            stream.Write(encoded);
            stream.Flush();
        }
        catch (IOException)
        {
            // Preferences are best effort and must never block startup or archive operations.
        }
        catch (IsolatedStorageException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (SecurityException)
        {
        }
        catch (NotSupportedException)
        {
        }
    }

    internal static string? DecodeValue(ReadOnlySpan<byte> encoded) => DecodeValue(encoded, MaxValueBytes);

    private static string? DecodeValue(ReadOnlySpan<byte> encoded, int limit)
    {
        if (encoded.Length <= 0 || encoded.Length > limit)
        {
            return null;
        }

        try
        {
            return StrictUtf8.GetString(encoded);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static void ValidateKey(string key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (key.Length > MaxKeyCharacters
            || key.Any(character => character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.')))
        {
            throw new ArgumentException("A settings key contains unsupported characters.", nameof(key));
        }
    }
}
