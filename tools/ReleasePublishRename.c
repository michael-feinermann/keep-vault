#define _DARWIN_C_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef RENAME_SWAP
#define RENAME_SWAP 0x00000002
#endif
#ifndef RENAME_EXCL
#define RENAME_EXCL 0x00000004
#endif

enum {
    ExitUsage = 64,
    ExitParentInvalid = 65,
    ExitSourceInvalid = 66,
    ExitTargetInvalid = 67,
    ExitIdentityMismatch = 68,
    ExitRenameFailed = 69,
    ExitRollbackFailed = 70
};

static bool parse_uintmax(const char *text, uintmax_t *value)
{
    char *end = NULL;
    errno = 0;
    uintmax_t parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *value = parsed;
    return true;
}

static bool parse_identity(const char *text, uintmax_t *device, uintmax_t *inode)
{
    const char *separator = strchr(text, ':');
    if (separator == NULL || separator == text || separator[1] == '\0') {
        return false;
    }

    size_t device_length = (size_t)(separator - text);
    if (device_length >= 64) {
        return false;
    }

    char device_text[64];
    memcpy(device_text, text, device_length);
    device_text[device_length] = '\0';
    return parse_uintmax(device_text, device)
        && parse_uintmax(separator + 1, inode);
}

static bool is_single_component(const char *name)
{
    return name != NULL
        && name[0] != '\0'
        && strcmp(name, ".") != 0
        && strcmp(name, "..") != 0
        && strchr(name, '/') == NULL;
}

static bool identity_matches(const struct stat *status,
                             uintmax_t expected_device,
                             uintmax_t expected_inode)
{
    return (uintmax_t)status->st_dev == expected_device
        && (uintmax_t)status->st_ino == expected_inode;
}

static int require_entry(int parent_descriptor,
                         const char *name,
                         uintmax_t expected_device,
                         uintmax_t expected_inode,
                         mode_t expected_type,
                         mode_t *actual_type)
{
    struct stat status;
    if (fstatat(parent_descriptor, name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    mode_t type = status.st_mode & S_IFMT;
    if (!identity_matches(&status, expected_device, expected_inode)
        || (type != S_IFREG && type != S_IFDIR)
        || (expected_type != 0 && type != expected_type)) {
        errno = ESTALE;
        return -1;
    }
    if (actual_type != NULL) {
        *actual_type = type;
    }
    return 0;
}

static bool entry_is_absent(int parent_descriptor, const char *name)
{
    struct stat status;
    errno = 0;
    return fstatat(parent_descriptor, name, &status, AT_SYMLINK_NOFOLLOW) != 0
        && errno == ENOENT;
}

/* The production helper never pauses here. The adversarial self-test compiles
   a separate binary with this hook so it can replace the source after the
   identity precheck and prove that the helper restores the public namespace. */
static int wait_for_test_race(void)
{
#ifdef KEEPVAULT_RELEASE_PUBLISH_TEST_HOOKS
    const char *ready_path = getenv("KEEPVAULT_RENAME_TEST_READY");
    const char *continue_path = getenv("KEEPVAULT_RENAME_TEST_CONTINUE");
    if (ready_path == NULL && continue_path == NULL) {
        return 0;
    }
    if (ready_path == NULL || continue_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    int ready = open(ready_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ready < 0 || close(ready) != 0) {
        return -1;
    }
    for (unsigned int attempt = 0; attempt < 30000; ++attempt) {
        if (access(continue_path, F_OK) == 0) {
            return 0;
        }
        if (errno != ENOENT) {
            return -1;
        }
        usleep(1000);
    }
    errno = ETIMEDOUT;
    return -1;
#else
    return 0;
#endif
}

static bool rollback_mismatched_rename(bool swap,
                                       int source_parent_descriptor,
                                       const char *source_name,
                                       int target_parent_descriptor,
                                       const char *target_name,
                                       uintmax_t expected_target_device,
                                       uintmax_t expected_target_inode,
                                       mode_t expected_type)
{
    struct stat source_after;
    struct stat target_after;
    if (fstatat(target_parent_descriptor, target_name, &target_after,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return false;
    }
    mode_t target_type = target_after.st_mode & S_IFMT;
    if ((target_type != S_IFREG && target_type != S_IFDIR)
        || target_type != expected_type) {
        errno = ESTALE;
        return false;
    }

    if (swap) {
        if (fstatat(source_parent_descriptor, source_name, &source_after,
                    AT_SYMLINK_NOFOLLOW) != 0
            || !identity_matches(&source_after,
                                 expected_target_device,
                                 expected_target_inode)
            || (source_after.st_mode & S_IFMT) != expected_type) {
            errno = ESTALE;
            return false;
        }
        if (renameatx_np(source_parent_descriptor, source_name,
                         target_parent_descriptor, target_name,
                         RENAME_SWAP) != 0) {
            return false;
        }
        return require_entry(target_parent_descriptor, target_name,
                             expected_target_device, expected_target_inode,
                             expected_type, NULL) == 0
            && require_entry(source_parent_descriptor, source_name,
                             (uintmax_t)target_after.st_dev,
                             (uintmax_t)target_after.st_ino,
                             expected_type, NULL) == 0;
    }

    if (!entry_is_absent(source_parent_descriptor, source_name)) {
        errno = ESTALE;
        return false;
    }
    if (renameatx_np(target_parent_descriptor, target_name,
                     source_parent_descriptor, source_name,
                     RENAME_EXCL) != 0) {
        return false;
    }
    return entry_is_absent(target_parent_descriptor, target_name)
        && require_entry(source_parent_descriptor, source_name,
                         (uintmax_t)target_after.st_dev,
                         (uintmax_t)target_after.st_ino,
                         expected_type, NULL) == 0;
}

int main(int argc, char **argv)
{
    if (argc != 10) {
        fputs("Usage: ReleasePublishRename MODE SOURCE_PARENT SOURCE TARGET_PARENT TARGET "
              "SOURCE_PARENT_DEV:INO TARGET_PARENT_DEV:INO SOURCE_DEV:INO TARGET_DEV:INO|-\n",
              stderr);
        return ExitUsage;
    }

    bool swap = strcmp(argv[1], "swap") == 0;
    bool exclusive = strcmp(argv[1], "exclusive") == 0;
    if ((!swap && !exclusive)
        || !is_single_component(argv[3])
        || !is_single_component(argv[5])) {
        return ExitUsage;
    }

    uintmax_t source_parent_device;
    uintmax_t source_parent_inode;
    uintmax_t target_parent_device;
    uintmax_t target_parent_inode;
    uintmax_t source_device;
    uintmax_t source_inode;
    uintmax_t target_device = 0;
    uintmax_t target_inode = 0;
    if (!parse_identity(argv[6], &source_parent_device, &source_parent_inode)
        || !parse_identity(argv[7], &target_parent_device, &target_parent_inode)
        || !parse_identity(argv[8], &source_device, &source_inode)
        || (swap && !parse_identity(argv[9], &target_device, &target_inode))
        || (exclusive && strcmp(argv[9], "-") != 0)) {
        return ExitUsage;
    }

    int source_parent_descriptor = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (source_parent_descriptor < 0) {
        return ExitParentInvalid;
    }
    int target_parent_descriptor = open(argv[4], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (target_parent_descriptor < 0) {
        close(source_parent_descriptor);
        return ExitParentInvalid;
    }

    struct stat source_parent_status;
    struct stat target_parent_status;
    if (fstat(source_parent_descriptor, &source_parent_status) != 0
        || fstat(target_parent_descriptor, &target_parent_status) != 0
        || !S_ISDIR(source_parent_status.st_mode)
        || !S_ISDIR(target_parent_status.st_mode)
        || !identity_matches(&source_parent_status, source_parent_device, source_parent_inode)
        || !identity_matches(&target_parent_status, target_parent_device, target_parent_inode)
        || source_parent_status.st_dev != target_parent_status.st_dev) {
        close(target_parent_descriptor);
        close(source_parent_descriptor);
        return ExitParentInvalid;
    }

    mode_t source_type = 0;
    if (require_entry(source_parent_descriptor, argv[3], source_device, source_inode, 0, &source_type) != 0) {
        close(target_parent_descriptor);
        close(source_parent_descriptor);
        return ExitSourceInvalid;
    }

    if (swap) {
        if (require_entry(target_parent_descriptor, argv[5], target_device, target_inode, source_type, NULL) != 0) {
            close(target_parent_descriptor);
            close(source_parent_descriptor);
            return ExitTargetInvalid;
        }
    } else {
        struct stat unexpected;
        if (fstatat(target_parent_descriptor, argv[5], &unexpected, AT_SYMLINK_NOFOLLOW) == 0
            || errno != ENOENT) {
            close(target_parent_descriptor);
            close(source_parent_descriptor);
            return ExitTargetInvalid;
        }
    }

    if (wait_for_test_race() != 0) {
        close(target_parent_descriptor);
        close(source_parent_descriptor);
        return ExitRenameFailed;
    }

    /* Catchable termination must not split the rename from its identity check
       and compensating rename. The caller's EXIT trap can then act on one
       complete result rather than an interrupt-sized intermediate state. */
    sigset_t blocked_signals;
    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGINT);
    sigaddset(&blocked_signals, SIGTERM);
    sigaddset(&blocked_signals, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &blocked_signals, NULL) != 0) {
        close(target_parent_descriptor);
        close(source_parent_descriptor);
        return ExitRenameFailed;
    }

    unsigned int flags = swap ? RENAME_SWAP : RENAME_EXCL;
    if (renameatx_np(source_parent_descriptor, argv[3], target_parent_descriptor, argv[5], flags) != 0) {
        close(target_parent_descriptor);
        close(source_parent_descriptor);
        return ExitRenameFailed;
    }

    bool valid = require_entry(target_parent_descriptor, argv[5], source_device, source_inode, source_type, NULL) == 0;
    if (swap) {
        valid = valid
            && require_entry(source_parent_descriptor, argv[3], target_device, target_inode, source_type, NULL) == 0;
    } else {
        valid = valid && entry_is_absent(source_parent_descriptor, argv[3]);
    }

    if (!valid) {
        bool rolled_back = rollback_mismatched_rename(
            swap,
            source_parent_descriptor, argv[3],
            target_parent_descriptor, argv[5],
            target_device, target_inode,
            source_type);
        close(target_parent_descriptor);
        close(source_parent_descriptor);
        if (rolled_back) {
            fputs("release_publish_identity_mismatch_rolled_back=true\n", stderr);
            return ExitIdentityMismatch;
        }
        fputs("release_publish_rollback_failed=true\n", stderr);
        return ExitRollbackFailed;
    }

    int target_close_status = close(target_parent_descriptor);
    int source_close_status = close(source_parent_descriptor);
    if (target_close_status != 0 || source_close_status != 0) {
        fputs("release_publish_descriptor_close_failed=true\n", stderr);
        return ExitRollbackFailed;
    }

    fputs(swap
        ? "release_publish_swap=complete\n"
        : "release_publish_exclusive=complete\n",
        stdout);
    return 0;
}
