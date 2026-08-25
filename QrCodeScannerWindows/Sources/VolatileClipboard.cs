using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Threading;

namespace QrScanner;

// The copy button, and the one place a scanned value leaves this process.
//
// Everything else here is arranged so the payload never reaches storage. The
// clipboard is the exception that cannot be argued away: it is owned by the
// system, not by this app, and Windows may keep it in clipboard history and -
// with the cloud clipboard - hand it to the user's other devices. No setting
// available to an application changes that on its own.
//
// What can be done is done. The item carries the three formats Windows itself
// defines for exactly this case, so history, cloud sync and third-party
// clipboard monitors are asked to leave it alone; it is cleared again after a
// short delay; and the delay is stated in the interface rather than left as a
// surprise. What cannot be done is claimed nowhere: see README.md.

public sealed class VolatileClipboard : IDisposable
{
    /// <summary>
    /// Keeps the entry out of the Windows clipboard history (Win+V).
    /// </summary>
    private const string CanIncludeInClipboardHistory = "CanIncludeInClipboardHistory";

    /// <summary>
    /// Keeps the entry from being synchronised to the user's other devices.
    /// </summary>
    private const string CanUploadToCloudClipboard = "CanUploadToCloudClipboard";

    /// <summary>
    /// Asks third-party clipboard managers not to record the entry. A
    /// convention rather than an enforcement, which is why the clearing timer
    /// exists as well.
    /// </summary>
    private const string ExcludeFromMonitorProcessing = "ExcludeClipboardContentFromMonitorProcessing";

    /// <summary>
    /// A private, random marker that proves the current clipboard entry is the
    /// exact DataObject this instance placed there. A sequence number alone is
    /// racy: another process can replace the clipboard between SetDataObject
    /// and GetClipboardSequenceNumber, making its entry look like ours.
    /// </summary>
    private const string OwnershipFormat = "KeepVault.QrScanner.ClipboardOwner.v1";

    private static readonly TimeSpan ClearRetryInterval = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Long enough to switch windows and paste, short enough that the value is
    /// not still sitting there hours later.
    /// </summary>
    public TimeSpan Lifetime { get; }

    private readonly DispatcherTimer _expiry;
    private uint? _sequenceAtCopy;
    private byte[]? _ownershipToken;
    private Action? _onExpiry;
    private bool _disposed;

    public VolatileClipboard(TimeSpan? lifetime = null)
    {
        Lifetime = lifetime ?? TimeSpan.FromSeconds(90);
        _expiry = new DispatcherTimer { Interval = Lifetime };
        _expiry.Tick += (_, _) => ClearIfStillOurs();
    }

    /// <summary>
    /// Puts the payload on the clipboard and schedules its removal.
    /// </summary>
    /// <param name="onExpiry">
    /// Run when the value is cleared, so the interface can stop telling the
    /// user it is available to paste.
    /// </param>
    public void Copy(string payload, Action onExpiry)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(onExpiry);

        byte[] ownershipToken = RandomNumberGenerator.GetBytes(32);
        var data = new DataObject();
        data.SetData(DataFormats.UnicodeText, payload);
        data.SetData(CanIncludeInClipboardHistory, FalseDword());
        data.SetData(CanUploadToCloudClipboard, FalseDword());
        data.SetData(ExcludeFromMonitorProcessing, new MemoryStream());
        data.SetData(OwnershipFormat, new MemoryStream(ownershipToken, writable: false));

        // Not the "copy" overload: leaving the data on the clipboard after this
        // process exits would outlive every guarantee made above, and the whole
        // point is that the value has a short life.
        try
        {
            Clipboard.SetDataObject(data, copy: false);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(ownershipToken);
            throw;
        }

        if (_ownershipToken is not null)
        {
            CryptographicOperations.ZeroMemory(_ownershipToken);
        }

        _ownershipToken = ownershipToken;
        _sequenceAtCopy = GetClipboardSequenceNumber();
        _onExpiry = onExpiry;
        _expiry.Stop();
        _expiry.Interval = Lifetime;
        _expiry.Start();
    }

    /// <summary>
    /// Removes the value, but only if it is still the one this app put there.
    /// </summary>
    /// <remarks>
    /// The user may well have copied something else in the meantime, and wiping
    /// their current clipboard because a scan expired would be its own small
    /// disaster. The sequence number is what tells the two cases apart.
    /// </remarks>
    public void ClearIfStillOurs()
    {
        _expiry.Stop();
        uint? stamp = _sequenceAtCopy;
        byte[]? token = _ownershipToken;
        if (stamp is null || token is null)
        {
            CompleteExpiry();
            return;
        }

        uint currentSequence = GetClipboardSequenceNumber();
        if (currentSequence != stamp)
        {
            // Somebody copied something else. The scanned value is no longer
            // the active clipboard entry, and clearing would destroy theirs.
            CompleteExpiry();
            return;
        }

        bool stillOurs;
        try
        {
            stillOurs = ClipboardTokenMatches(token);
        }
        catch (Exception exception) when (exception is ExternalException or InvalidOperationException)
        {
            ScheduleRetry();
            return;
        }

        if (!stillOurs)
        {
            // Covers the SetDataObject/GetClipboardSequenceNumber race: the
            // sequence can belong to a replacement entry, but its private
            // random marker cannot.
            CompleteExpiry();
            return;
        }

        try
        {
            Clipboard.Clear();
        }
        catch (Exception exception) when (exception is ExternalException or InvalidOperationException)
        {
            // Clipboard locks are transient. Keep ownership state and retry;
            // dropping it here leaves the factor indefinitely while the UI
            // incorrectly claims it was removed.
            ScheduleRetry();
            return;
        }

        CompleteExpiry();
    }

    private static bool ClipboardTokenMatches(byte[] expected)
    {
        object? marker = Clipboard.GetData(OwnershipFormat);
        byte[]? actual = marker switch
        {
            byte[] bytes => [.. bytes],
            MemoryStream stream => stream.ToArray(),
            _ => null,
        };
        if (actual is null)
        {
            return false;
        }

        try
        {
            return actual.Length == expected.Length
                && CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private void ScheduleRetry()
    {
        if (_disposed)
        {
            return;
        }

        _expiry.Interval = ClearRetryInterval;
        _expiry.Start();
    }

    private void CompleteExpiry()
    {
        _expiry.Stop();
        _sequenceAtCopy = null;
        if (_ownershipToken is not null)
        {
            CryptographicOperations.ZeroMemory(_ownershipToken);
            _ownershipToken = null;
        }

        Action? onExpiry = _onExpiry;
        _onExpiry = null;
        onExpiry?.Invoke();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _expiry.Stop();
        if (_ownershipToken is not null)
        {
            CryptographicOperations.ZeroMemory(_ownershipToken);
            _ownershipToken = null;
        }

        _sequenceAtCopy = null;
        _onExpiry = null;
    }

    /// <summary>
    /// A DWORD zero, which is how the two Windows clipboard formats spell "no".
    /// </summary>
    private static MemoryStream FalseDword() => new([0, 0, 0, 0]);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();
}
