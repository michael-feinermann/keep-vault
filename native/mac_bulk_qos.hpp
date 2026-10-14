#ifndef KEEPVAULT_MAC_BULK_QOS_HPP
#define KEEPVAULT_MAC_BULK_QOS_HPP

#if defined(__APPLE__)
#include <pthread.h>
#include <pthread/qos.h>
#endif

// Utility is Apple's classification for longer, progress-reporting work.
// This does not select CPUs or override process limits. Unsupported/opted-out
// threads retain their policy. The main thread is never reclassified.
// https://developer.apple.com/library/archive/documentation/Performance/Conceptual/EnergyGuide-iOS/PrioritizeWorkWithQoS.html
class keepvault_mac_bulk_qos_scope {
public:
    explicit keepvault_mac_bulk_qos_scope(bool enabled = true) noexcept {
#if defined(__APPLE__)
        if (!enabled || pthread_main_np()) return;
        if (pthread_get_qos_class_np(pthread_self(), &previous_, &relative_) != 0) return;
        // UNSPECIFIED is not accepted by the setter, so cannot be restored.
        if (previous_ != QOS_CLASS_DEFAULT && previous_ != QOS_CLASS_USER_INITIATED
            && previous_ != QOS_CLASS_USER_INTERACTIVE) return;
        active_ = pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) == 0;
#else
        (void)enabled;
#endif
    }
    keepvault_mac_bulk_qos_scope(const keepvault_mac_bulk_qos_scope&) = delete;
    keepvault_mac_bulk_qos_scope& operator=(const keepvault_mac_bulk_qos_scope&) = delete;
    ~keepvault_mac_bulk_qos_scope() noexcept { (void)restore(); }

    int restore() noexcept {
#if defined(__APPLE__)
        if (!active_) return 0;
        const int status = pthread_set_qos_class_self_np(previous_, relative_);
        if (status == 0) active_ = false;
        return status;
#else
        return 0;
#endif
    }
private:
#if defined(__APPLE__)
    qos_class_t previous_ = QOS_CLASS_UNSPECIFIED;
    int relative_ = 0;
    bool active_ = false;
#endif
};

#endif
