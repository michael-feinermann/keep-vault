using System.ComponentModel;
using System.Runtime.InteropServices;

namespace KalynaArchiver.Services;

// Apple classifies longer, progress-reporting work as Utility. This scope is
// thread-bound and must only surround synchronous CPU work, never an await.
// https://developer.apple.com/library/archive/documentation/Performance/Conceptual/EnergyGuide-iOS/PrioritizeWorkWithQoS.html
internal readonly ref struct MacCpuWorkerQos
{
    private const uint Utility = 0x11;
    private readonly nuint _thread;
    private readonly uint _previousClass;
    private readonly int _previousPriority;

    private MacCpuWorkerQos(nuint thread, uint previousClass, int previousPriority)
    {
        _thread = thread;
        _previousClass = previousClass;
        _previousPriority = previousPriority;
    }

    internal static MacCpuWorkerQos EnterSynchronousScope()
    {
        if (!OperatingSystem.IsMacOS() || pthread_main_np() != 0) return default;
        nuint thread = pthread_self();
        if (pthread_get_qos_class_np(thread, out uint previousClass, out int previousPriority) != 0)
            return default;
        // UNSPECIFIED cannot be restored with pthread_set_qos_class_self_np.
        // Preserve explicit Utility/Background priorities and future classes.
        if (previousClass is not (0x15 or 0x19 or 0x21)) return default;
        if (pthread_set_qos_class_self_np(Utility, 0) != 0) return default;
        return new MacCpuWorkerQos(thread, previousClass, previousPriority);
    }

    public void Dispose()
    {
        if (_thread == 0) return;
        if (pthread_self() != _thread)
            throw new InvalidOperationException("A CPU QoS scope crossed a native thread boundary.");
        int result = pthread_set_qos_class_self_np(_previousClass, _previousPriority);
        if (result != 0)
            throw new Win32Exception(result, "Unable to restore the CPU worker QoS class.");
    }

    [DllImport("/usr/lib/libSystem.B.dylib")]
    private static extern nuint pthread_self();
    [DllImport("/usr/lib/libSystem.B.dylib")]
    private static extern int pthread_main_np();
    [DllImport("/usr/lib/libSystem.B.dylib")]
    private static extern int pthread_get_qos_class_np(nuint thread, out uint qosClass, out int relativePriority);
    [DllImport("/usr/lib/libSystem.B.dylib")]
    private static extern int pthread_set_qos_class_self_np(uint qosClass, int relativePriority);
}
