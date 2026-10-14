/* Isolated regression for the real Argon2 rolling-worker failure path.
 * Cryptographic fill work is replaced by controlled Windows workers. Failed
 * join/detach calls leave one worker blocked until the core waits for its
 * completion. The free interceptor detects premature reclamation and drains
 * that worker before freeing, so the negative control itself never uses freed
 * memory. This executable is never linked into a shipped native component. */
#if !defined(_WIN32)
#error This fault harness exercises the Windows thread boundary.
#endif
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BOOL WINAPI test_yield(void);
static void test_free(void* pointer);

#define SwitchToThread test_yield
#define free test_free
#define fill_segment test_fill_segment
#define argon2_thread_create test_thread_create
#define argon2_thread_join test_thread_join
#define argon2_thread_detach test_thread_detach
#define argon2_thread_exit test_thread_exit
#if defined(KEEPVAULT_TEST_UNSAFE_COMPLETION)
#include "argon2-core-before.c"
#else
#include "../external/phc-winner-argon2/src/core.c"
#endif
#undef SwitchToThread
#undef free

enum { TEST_LANES = 4, TEST_THREADS = 2 };
static HANDLE worker_handles[TEST_LANES];
static int worker_closed[TEST_LANES];
static HANDLE delayed_worker_release;
static volatile LONG delayed_worker_finished;
static volatile LONG premature_free;
static volatile LONG completion_waits;
static uint32_t created_workers;
static int fail_late_create;
static int fault_active;
static int successful_joins;

static void require(int condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "harness_failure=%s\n", message);
        abort();
    }
}

static void drain_workers(void) {
    require(SetEvent(delayed_worker_release) != 0, "release worker");
    for (uint32_t index = 0; index < created_workers; ++index) {
        if (!worker_closed[index]) {
            require(WaitForSingleObject(worker_handles[index], 10000) == WAIT_OBJECT_0,
                    "worker did not finish before the bounded timeout");
        }
    }
}

static BOOL WINAPI test_yield(void) {
    InterlockedIncrement(&completion_waits);
    require(SetEvent(delayed_worker_release) != 0, "release during completion wait");
    return SwitchToThread();
}

static void test_free(void* pointer) {
    if (pointer != NULL && created_workers >= 3
        && InterlockedCompareExchange(&delayed_worker_finished, 0, 0) == 0) {
        /* The third worker is still inside fill_segment and holds the instance
         * and completion pointer. Reclaiming any phase table here is unsafe. */
        InterlockedExchange(&premature_free, 1);
        drain_workers();
    }
    free(pointer);
}

void test_fill_segment(const argon2_instance_t* instance, argon2_position_t position) {
    (void)instance;
    if (position.lane == 2) {
        require(WaitForSingleObject(delayed_worker_release, 10000) == WAIT_OBJECT_0,
                "delayed worker was never released");
        InterlockedExchange(&delayed_worker_finished, 1);
    }
}

int test_thread_create(argon2_thread_handle_t* handle, argon2_thread_func_t function, void* arguments) {
    argon2_thread_data* job = (argon2_thread_data*)arguments;
    uint32_t lane = job->pos.lane;
    require(lane < TEST_LANES, "unexpected lane");
    if (fail_late_create && lane == 3) {
        require(successful_joins == 2 && created_workers == 3, "create fault was not late");
        fault_active = 1;
        return -1;
    }
    *handle = _beginthreadex(NULL, 0, function, arguments, 0, NULL);
    require(*handle != 0, "real Windows thread creation");
    worker_handles[lane] = (HANDLE)*handle;
    ++created_workers;
    /* Completed lanes zero and one deterministically inflate the cumulative
     * completion counter before the rolling-window failure is injected. */
    if (lane < 2)
        require(WaitForSingleObject(worker_handles[lane], 10000) == WAIT_OBJECT_0,
                "early worker completion");
    return 0;
}

int test_thread_join(argon2_thread_handle_t handle) {
    if (!fail_late_create && successful_joins == 1 && created_workers == 3)
        fault_active = 1;
    if (fault_active) return -1;
    require(WaitForSingleObject((HANDLE)handle, 10000) == WAIT_OBJECT_0, "ordinary join");
    for (uint32_t index = 0; index < created_workers; ++index) {
        if (worker_handles[index] == (HANDLE)handle) {
            require(!worker_closed[index], "duplicate close");
            require(CloseHandle((HANDLE)handle) != 0, "close joined worker");
            worker_closed[index] = 1;
            ++successful_joins;
            return 0;
        }
    }
    require(0, "unknown join handle");
    return -1;
}

int test_thread_detach(argon2_thread_handle_t handle) {
    (void)handle;
    require(fault_active, "detach without fault");
    return -1;
}

void test_thread_exit(void) {
    /* Returning lets _beginthreadex perform its normal thread teardown. */
}

static int run_fault(int create_failure) {
    argon2_instance_t instance;
    memset(&instance, 0, sizeof(instance));
    memset(worker_handles, 0, sizeof(worker_handles));
    memset(worker_closed, 0, sizeof(worker_closed));
    delayed_worker_finished = premature_free = completion_waits = 0;
    created_workers = 0;
    successful_joins = fault_active = 0;
    fail_late_create = create_failure;
    delayed_worker_release = CreateEventW(NULL, TRUE, FALSE, NULL);
    require(delayed_worker_release != NULL, "create delayed-worker event");
    instance.lanes = TEST_LANES;
    instance.threads = TEST_THREADS;
    instance.passes = 1;
    int result = fill_memory_blocks(&instance);
    require(result == ARGON2_THREAD_FAIL, "thread error was not preserved");
    require(fault_active && created_workers == 3, "failure boundary not exercised");
    drain_workers();
    for (uint32_t index = 0; index < created_workers; ++index)
        if (!worker_closed[index]) require(CloseHandle(worker_handles[index]) != 0, "final close");
    require(CloseHandle(delayed_worker_release) != 0, "close worker event");
    int unsafe = InterlockedCompareExchange(&premature_free, 0, 0) != 0;
    printf("argon2_late_%s=%s completion_waits=%ld created=%u successful_joins=%d\n",
           create_failure ? "create" : "join",
           unsafe ? "premature_free_detected" : "all_workers_completed_before_free",
           completion_waits, created_workers, successful_joins);
    if (!unsafe) require(completion_waits > 0, "pending worker did not require a completion wait");
    return unsafe;
}

int main(void) {
    int failed = run_fault(0);
    failed |= run_fault(1);
    return failed;
}
