using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Avalonia.Platform.Storage;

namespace KalynaArchiver.Gui;

internal sealed partial class MacSecurityScopedResourceLease : IDisposable
{
    private const uint Utf8Encoding = 0x08000100;
    private static readonly nint StartAccessSelector = SelRegisterName("startAccessingSecurityScopedResource");
    private static readonly nint StopAccessSelector = SelRegisterName("stopAccessingSecurityScopedResource");

    private nint _url;
    [ThreadStatic] private static DisposeObservationScope? _disposeObservationForTests;

    // Passive scalar observation exists only while a test scope is active.
    // It does not replace native acquisition/release or accept callbacks/data.
    internal static DisposeObservationScope ObserveDisposeInvocationsForTests() => new();

    internal sealed class DisposeObservationScope : IDisposable
    {
        private readonly DisposeObservationScope? _previous;
        internal long Count { get; private set; }
        internal DisposeObservationScope()
        {
            _previous = _disposeObservationForTests;
            _disposeObservationForTests = this;
        }
        internal void Record() { unchecked { ++Count; } }
        public void Dispose()
        {
            if (ReferenceEquals(_disposeObservationForTests, this)) _disposeObservationForTests = _previous;
        }
    }

    private MacSecurityScopedResourceLease(nint url)
    {
        _url = url;
    }

    internal static MacSecurityScopedResourceLease Acquire(IStorageItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return Acquire(item.Path);
    }

    internal static MacSecurityScopedResourceLease Acquire(Uri itemUri)
    {
        ArgumentNullException.ThrowIfNull(itemUri);
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("Security-scoped URL leases are only available on macOS.");
        }

        if (!itemUri.IsAbsoluteUri || !itemUri.IsFile)
        {
            throw new NotSupportedException("The selected storage item does not expose an absolute file URL.");
        }

        byte[] uriBytes = System.Text.Encoding.UTF8.GetBytes(itemUri.AbsoluteUri);
        nint uriString = 0;
        nint url = 0;
        try
        {
            uriString = CFStringCreateWithBytes(
                0,
                uriBytes,
                uriBytes.Length,
                Utf8Encoding,
                isExternalRepresentation: false);
            if (uriString == 0)
            {
                throw new InvalidOperationException("Foundation could not create the security-scoped URL string.");
            }

            url = CFURLCreateWithString(0, uriString, 0);
            if (url == 0)
            {
                throw new InvalidOperationException("Foundation could not create the security-scoped file URL.");
            }

            // startAccessingSecurityScopedResource reports NO both when access is
            // refused and when the URL simply is not security-scoped. The latter
            // is the ordinary case here: a drop and an in-process open panel
            // hand over plain file URLs for which the sandbox has already
            // extended access to this process, and only URLs resolved from a
            // security-scoped bookmark ever answer YES. Treating NO as a denial
            // rejected every file the user picked or dropped.
            //
            // Whether access truly exists is therefore established by reading
            // the item, not by this call, and the caller fails closed when the
            // path cannot be reached. Access must also not be stopped for a URL
            // that never started, so an unscoped lease holds no URL to release.
            if (!ObjcMessageSendBool(url, StartAccessSelector))
            {
                return new MacSecurityScopedResourceLease(0);
            }

            nint ownedUrl = url;
            url = 0;
            return new MacSecurityScopedResourceLease(ownedUrl);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(uriBytes);
            if (url != 0)
            {
                CFRelease(url);
            }

            if (uriString != 0)
            {
                CFRelease(uriString);
            }
        }
    }

    public void Dispose()
    {
        _disposeObservationForTests?.Record();
        GC.SuppressFinalize(this);
        nint url = Interlocked.Exchange(ref _url, 0);

        // An unscoped lease holds nothing: stopping access for a URL that never
        // started is an unbalanced call.
        if (url == 0)
        {
            return;
        }

        ObjcMessageSendVoid(url, StopAccessSelector);
        CFRelease(url);
    }

    ~MacSecurityScopedResourceLease()
    {
        Dispose();
    }

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFStringCreateWithBytes")]
    private static partial nint CFStringCreateWithBytes(
        nint allocator,
        byte[] bytes,
        nint length,
        uint encoding,
        [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFURLCreateWithString")]
    private static partial nint CFURLCreateWithString(nint allocator, nint urlString, nint baseUrl);

    [LibraryImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", EntryPoint = "CFRelease")]
    private static partial void CFRelease(nint value);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "sel_registerName", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint SelRegisterName(string name);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    [return: MarshalAs(UnmanagedType.I1)]
    private static partial bool ObjcMessageSendBool(nint receiver, nint selector);

    [LibraryImport("/usr/lib/libobjc.A.dylib", EntryPoint = "objc_msgSend")]
    private static partial void ObjcMessageSendVoid(nint receiver, nint selector);
}

internal sealed class MacStorageAccessLease : IDisposable
{
    private readonly object _gate = new();
    private readonly MacSecurityScopedResourceLease _nativeLease;
    private IStorageItem? _item;
    private bool _disposed;
    private bool _nativeDisposed;
    private bool _disposing;

    private MacStorageAccessLease(IStorageItem item, MacSecurityScopedResourceLease nativeLease)
    {
        _item = item;
        _nativeLease = nativeLease;
    }

    internal IStorageItem Item
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _item!;
            }
        }
    }

    internal bool OwnsItem(IStorageItem item)
    {
        lock (_gate) return ReferenceEquals(_item, item);
    }

    internal static MacStorageAccessLease Acquire(IStorageItem item)
    {
        MacSecurityScopedResourceLease nativeLease = MacSecurityScopedResourceLease.Acquire(item);
        return new MacStorageAccessLease(item, nativeLease);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            if (_disposing) return;
            _disposing = true;
            try
            {
                List<Exception>? failures = null;
                if (!_nativeDisposed)
                {
                    try { _nativeLease.Dispose(); _nativeDisposed = true; }
                    catch (Exception failure) { (failures ??= []).Add(failure); }
                }
                if (_item is { } item)
                {
                    try { item.Dispose(); _item = null; }
                    catch (Exception failure) { (failures ??= []).Add(failure); }
                }
                if (failures is not null)
                {
                    // Keep only unsuccessful cleanup owners for an explicit retry.
                    throw new AggregateException("Storage access cleanup failed.", failures);
                }
            }
            finally { _disposing = false; }
        }
    }
}
