#include "../mac_bulk_qos.hpp"
#include <atomic>
#include <cstdio>
#include <stdexcept>
#include <thread>

static std::atomic<unsigned> checks{0};
static void require(bool condition) {
    if (!condition) throw std::runtime_error("native QoS assertion failed");
    ++checks;
}
static void state(qos_class_t expected, int relative) {
    qos_class_t actual; int priority;
    require(pthread_get_qos_class_np(pthread_self(), &actual, &priority) == 0);
    require(actual == expected && priority == relative);
}
int main() {
    qos_class_t initial; int initial_priority;
    require(pthread_main_np() != 0);
    require(pthread_get_qos_class_np(pthread_self(), &initial, &initial_priority) == 0);
    { keepvault_mac_bulk_qos_scope scope; state(initial, initial_priority); }
    state(initial, initial_priority);
    std::exception_ptr failure;
    std::thread worker([&] {
        try {
            for (const auto qos : {QOS_CLASS_DEFAULT, QOS_CLASS_USER_INITIATED, QOS_CLASS_USER_INTERACTIVE}) {
                for (int priority : {0, -5}) {
                    require(pthread_set_qos_class_self_np(qos, priority) == 0);
                    {
                        keepvault_mac_bulk_qos_scope outer;
                        state(QOS_CLASS_UTILITY, 0);
                        { keepvault_mac_bulk_qos_scope nested; state(QOS_CLASS_UTILITY, 0); }
                        state(QOS_CLASS_UTILITY, 0);
                    }
                    state(qos, priority);
                    try { keepvault_mac_bulk_qos_scope unwind; throw 1; }
                    catch (int) {}
                    state(qos, priority);
                    { keepvault_mac_bulk_qos_scope disabled(false); state(qos, priority); }
                    state(qos, priority);
                }
            }
            for (const auto qos : {QOS_CLASS_UTILITY, QOS_CLASS_BACKGROUND}) {
                require(pthread_set_qos_class_self_np(qos, -5) == 0);
                { keepvault_mac_bulk_qos_scope scope; state(qos, -5); }
                state(qos, -5);
            }
            // Explicitly opted-out disposable thread: UNSPECIFIED must stay so.
            sched_param parameters{};
            require(pthread_setschedparam(pthread_self(), SCHED_OTHER, &parameters) == 0);
            state(QOS_CLASS_UNSPECIFIED, 0);
            { keepvault_mac_bulk_qos_scope scope; state(QOS_CLASS_UNSPECIFIED, 0); }
            state(QOS_CLASS_UNSPECIFIED, 0);
        } catch (...) { failure = std::current_exception(); }
    });
    worker.join();
    if (failure) std::rethrow_exception(failure);
    std::printf("{\"status\":\"PASS\",\"checks\":%u,\"scope\":\"native thread QoS entry, nested/unwind restore, relative priority, main/background/unspecified preservation\"}\n", checks.load());
}
