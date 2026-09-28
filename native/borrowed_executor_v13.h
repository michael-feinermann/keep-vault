/* A process-wide managed executor is registered once per trusted module.
 * The call is synchronous: every submitted worker MUST finish before return,
 * including nonzero/error return. The grant includes the invoking thread.
 * Only function pointers are retained; job contexts and keys never are.
 */
#ifndef KEEPVAULT_BORROWED_EXECUTOR_V13_H
#define KEEPVAULT_BORROWED_EXECUTOR_V13_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32)
#include <windows.h>
#define KEEPVAULT_EXECUTOR_EXPORT __declspec(dllexport)
#else
#define KEEPVAULT_EXECUTOR_EXPORT __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
#include <atomic>
extern "C" {
#endif
typedef void (*keepvault_worker_v13)(void*, size_t);
typedef int (*keepvault_executor_v13)(size_t, keepvault_worker_v13, void*);
#ifdef __cplusplus
}
static std::atomic<keepvault_executor_v13> keepvault_registered_executor{nullptr};
static keepvault_executor_v13 keepvault_get_executor(void) noexcept {
    return keepvault_registered_executor.load(std::memory_order_acquire);
}
extern "C" KEEPVAULT_EXECUTOR_EXPORT int keepvault_v13_register_executor(keepvault_executor_v13 value) noexcept {
    if (value == nullptr) return 1;
    keepvault_executor_v13 expected = nullptr;
    return keepvault_registered_executor.compare_exchange_strong(expected,value,std::memory_order_acq_rel)
        || expected == value ? 0 : 1;
}
namespace keepvault {
template<class Worker> int execute_borrowed(size_t count, Worker& worker) noexcept {
    const auto executor = keepvault_get_executor();
    if (executor == nullptr) return -1; // Standalone native verification only.
    const int status = executor(count, [](void* context, size_t index) noexcept {
        (*static_cast<Worker*>(context))(index);
    }, &worker);
    return status == 0 ? 0 : 3;
}
}
#elif defined(_WIN32)
static keepvault_executor_v13 keepvault_registered_executor;
static keepvault_executor_v13 keepvault_get_executor(void) {
    return (keepvault_executor_v13)InterlockedCompareExchangePointer((void* volatile*)&keepvault_registered_executor,NULL,NULL);
}
KEEPVAULT_EXECUTOR_EXPORT int keepvault_v13_register_executor(keepvault_executor_v13 value) {
    if (value == NULL) return 1;
    keepvault_executor_v13 previous = (keepvault_executor_v13)InterlockedCompareExchangePointer((void* volatile*)&keepvault_registered_executor,(void*)value,NULL);
    return previous == NULL || previous == value ? 0 : 1;
}
#else
#include <stdatomic.h>
static _Atomic(keepvault_executor_v13) keepvault_registered_executor;
static keepvault_executor_v13 keepvault_get_executor(void) {
    return atomic_load_explicit(&keepvault_registered_executor,memory_order_acquire);
}
KEEPVAULT_EXECUTOR_EXPORT int keepvault_v13_register_executor(keepvault_executor_v13 value) {
    if (value == NULL) return 1;
    keepvault_executor_v13 expected = NULL;
    return atomic_compare_exchange_strong_explicit(&keepvault_registered_executor,&expected,value,memory_order_acq_rel,memory_order_acquire)
        || expected == value ? 0 : 1;
}
#endif
#endif
