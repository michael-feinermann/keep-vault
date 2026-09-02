using System.Runtime.InteropServices;

namespace KalynaArchiver.Services;

internal static partial class MacNativeAlert
{
    private const string ObjectiveCLibrary = "/usr/lib/libobjc.A.dylib";
    private const string AppKitLibrary = "/System/Library/Frameworks/AppKit.framework/AppKit";

    internal static void ShowCritical(string title, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        nint appKit = NativeLibrary.Load(AppKitLibrary);
        nint pool = 0;
        nint alert = 0;
        try
        {
            pool = AllocateAndInitialize("NSAutoreleasePool");
            nint applicationClass = RequireClass("NSApplication");
            _ = SendObject(applicationClass, RequireSelector("sharedApplication"));

            alert = AllocateAndInitialize("NSAlert");
            SendVoidObject(alert, RequireSelector("setMessageText:"), CreateString(title));
            SendVoidObject(alert, RequireSelector("setInformativeText:"), CreateString(message));
            SendVoidInteger(alert, RequireSelector("setAlertStyle:"), 2);
            _ = SendObjectObject(alert, RequireSelector("addButtonWithTitle:"), CreateString("Beenden"));
            _ = SendInteger(alert, RequireSelector("runModal"));
        }
        finally
        {
            if (alert != 0)
            {
                SendVoid(alert, RequireSelector("release"));
            }

            if (pool != 0)
            {
                SendVoid(pool, RequireSelector("drain"));
            }

            NativeLibrary.Free(appKit);
        }
    }

    private static nint AllocateAndInitialize(string className)
    {
        nint instance = SendObject(RequireClass(className), RequireSelector("alloc"));
        if (instance == 0)
        {
            throw new InvalidOperationException($"AppKit could not allocate {className}.");
        }

        nint initialized = SendObject(instance, RequireSelector("init"));
        if (initialized == 0)
        {
            throw new InvalidOperationException($"AppKit could not initialize {className}.");
        }

        return initialized;
    }

    private static nint CreateString(string value)
    {
        nint result = SendObjectUtf8(
            RequireClass("NSString"),
            RequireSelector("stringWithUTF8String:"),
            value);
        return result != 0
            ? result
            : throw new InvalidOperationException("AppKit could not create alert text.");
    }

    private static nint RequireClass(string name)
    {
        nint value = GetClass(name);
        return value != 0
            ? value
            : throw new InvalidOperationException($"AppKit class {name} is unavailable.");
    }

    private static nint RequireSelector(string name)
    {
        nint value = RegisterSelector(name);
        return value != 0
            ? value
            : throw new InvalidOperationException($"AppKit selector {name} is unavailable.");
    }

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_getClass", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint GetClass(string name);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "sel_registerName", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint RegisterSelector(string name);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
    private static partial nint SendObject(nint receiver, nint selector);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint SendObjectUtf8(nint receiver, nint selector, string value);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
    private static partial nint SendObjectObject(nint receiver, nint selector, nint value);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
    private static partial nint SendInteger(nint receiver, nint selector);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
    private static partial void SendVoid(nint receiver, nint selector);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
    private static partial void SendVoidObject(nint receiver, nint selector, nint value);

    [LibraryImport(ObjectiveCLibrary, EntryPoint = "objc_msgSend")]
    private static partial void SendVoidInteger(nint receiver, nint selector, nint value);
}
