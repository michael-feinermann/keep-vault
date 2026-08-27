#define _DARWIN_C_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef RENAME_EXCL
#define RENAME_EXCL 0x00000004
#endif

enum {
    ExitUsage = 64,
    ExitParentInvalid = 65,
    ExitQuarantineInvalid = 66,
    ExitRenameFailed = 67,
    ExitIdentityMismatch = 68,
    ExitDeleteFailed = 69
};

static void print_errno(const char *operation, const char *name)
{
    fprintf(stderr, "installer_bound_delete_error=%s:%s:%s\n",
            operation, name, strerror(errno));
}

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

static int open_bound_directory(const char *path,
                                uintmax_t expected_device,
                                uintmax_t expected_inode,
                                bool require_private)
{
    int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -1;
    }

    struct stat status;
    if (fstat(descriptor, &status) != 0
        || !S_ISDIR(status.st_mode)
        || !identity_matches(&status, expected_device, expected_inode)
        || (require_private
            && (status.st_uid != geteuid() || (status.st_mode & 07777) != 0700))) {
        int saved_errno = errno == 0 ? EPERM : errno;
        close(descriptor);
        errno = saved_errno;
        return -1;
    }

    return descriptor;
}

static int verify_entry_identity(int parent_descriptor,
                                 const char *name,
                                 const struct stat *expected)
{
    struct stat current;
    if (fstatat(parent_descriptor, name, &current, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }

    if (current.st_dev != expected->st_dev
        || current.st_ino != expected->st_ino
        || (current.st_mode & S_IFMT) != (expected->st_mode & S_IFMT)) {
        errno = ESTALE;
        return -1;
    }

    return 0;
}

static int remove_entry_bound(int parent_descriptor, const char *name);

static int empty_directory_bound(int directory_descriptor)
{
    int stream_descriptor = dup(directory_descriptor);
    if (stream_descriptor < 0) {
        return -1;
    }

    DIR *stream = fdopendir(stream_descriptor);
    if (stream == NULL) {
        int saved_errno = errno;
        close(stream_descriptor);
        errno = saved_errno;
        return -1;
    }

    /* dup() shares the directory offset on Darwin. Always rewind the stream
       before reading so a prior descriptor operation cannot hide entries. */
    rewinddir(stream);
    errno = 0;
    for (;;) {
        struct dirent *entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(stream);
                errno = saved_errno;
                return -1;
            }
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (!is_single_component(entry->d_name)
            || remove_entry_bound(directory_descriptor, entry->d_name) != 0) {
            int saved_errno = errno == 0 ? EINVAL : errno;
            closedir(stream);
            errno = saved_errno;
            return -1;
        }
    }

    return closedir(stream);
}

static int remove_entry_bound(int parent_descriptor, const char *name)
{
    struct stat before;
    if (fstatat(parent_descriptor, name, &before, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }

    if (!S_ISDIR(before.st_mode)) {
        if (verify_entry_identity(parent_descriptor, name, &before) != 0) {
            return -1;
        }
        return unlinkat(parent_descriptor, name, 0);
    }

    int directory_descriptor = openat(parent_descriptor, name,
                                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_descriptor < 0) {
        return -1;
    }

    struct stat opened;
    if (fstat(directory_descriptor, &opened) != 0
        || opened.st_dev != before.st_dev
        || opened.st_ino != before.st_ino
        || !S_ISDIR(opened.st_mode)) {
        int saved_errno = errno == 0 ? ESTALE : errno;
        close(directory_descriptor);
        errno = saved_errno;
        return -1;
    }

    if (empty_directory_bound(directory_descriptor) != 0) {
        int saved_errno = errno;
        close(directory_descriptor);
        errno = saved_errno;
        return -1;
    }

    if (verify_entry_identity(parent_descriptor, name, &opened) != 0) {
        int saved_errno = errno;
        close(directory_descriptor);
        errno = saved_errno;
        return -1;
    }

    if (close(directory_descriptor) != 0) {
        return -1;
    }

    return unlinkat(parent_descriptor, name, AT_REMOVEDIR);
}

static int make_quarantine_name(char *buffer, size_t buffer_size)
{
    for (unsigned int attempt = 0; attempt < 128; ++attempt) {
        uint64_t random_value = 0;
        arc4random_buf(&random_value, sizeof(random_value));
        int written = snprintf(buffer, buffer_size,
                               ".keep-vault-delete.%016" PRIx64, random_value);
        if (written < 0 || (size_t)written >= buffer_size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    errno = EEXIST;
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 9) {
        fputs("Usage: InstallerBoundDelete PARENT NAME PARENT_DEV PARENT_INO "
              "QUARANTINE QUARANTINE_DEV QUARANTINE_INO OBJECT_DEV:OBJECT_INO\n",
              stderr);
        return ExitUsage;
    }

    if (!is_single_component(argv[2])) {
        fputs("installer_bound_delete_error=invalid-source-name\n", stderr);
        return ExitUsage;
    }

    uintmax_t parent_device;
    uintmax_t parent_inode;
    uintmax_t quarantine_device;
    uintmax_t quarantine_inode;
    if (!parse_uintmax(argv[3], &parent_device)
        || !parse_uintmax(argv[4], &parent_inode)
        || !parse_uintmax(argv[6], &quarantine_device)
        || !parse_uintmax(argv[7], &quarantine_inode)) {
        fputs("installer_bound_delete_error=invalid-directory-identity\n", stderr);
        return ExitUsage;
    }

    const char *separator = strchr(argv[8], ':');
    if (separator == NULL || separator == argv[8] || separator[1] == '\0') {
        fputs("installer_bound_delete_error=invalid-object-identity\n", stderr);
        return ExitUsage;
    }

    size_t device_length = (size_t)(separator - argv[8]);
    if (device_length >= 64) {
        return ExitUsage;
    }
    char object_device_text[64];
    memcpy(object_device_text, argv[8], device_length);
    object_device_text[device_length] = '\0';

    uintmax_t object_device;
    uintmax_t object_inode;
    if (!parse_uintmax(object_device_text, &object_device)
        || !parse_uintmax(separator + 1, &object_inode)) {
        fputs("installer_bound_delete_error=invalid-object-identity\n", stderr);
        return ExitUsage;
    }

    int parent_descriptor = open_bound_directory(
        argv[1], parent_device, parent_inode, false);
    if (parent_descriptor < 0) {
        print_errno("open-parent", argv[1]);
        return ExitParentInvalid;
    }

    int quarantine_descriptor = open_bound_directory(
        argv[5], quarantine_device, quarantine_inode, true);
    if (quarantine_descriptor < 0) {
        print_errno("open-quarantine", argv[5]);
        close(parent_descriptor);
        return ExitQuarantineInvalid;
    }

    struct stat parent_status;
    struct stat quarantine_status;
    if (fstat(parent_descriptor, &parent_status) != 0
        || fstat(quarantine_descriptor, &quarantine_status) != 0) {
        print_errno("cross-device-quarantine", argv[5]);
        close(quarantine_descriptor);
        close(parent_descriptor);
        return ExitQuarantineInvalid;
    }
    if (parent_status.st_dev != quarantine_status.st_dev) {
        errno = EXDEV;
        print_errno("cross-device-quarantine", argv[5]);
        close(quarantine_descriptor);
        close(parent_descriptor);
        return ExitQuarantineInvalid;
    }

    char quarantine_name[128];
    bool renamed = false;
    for (unsigned int attempt = 0; attempt < 128; ++attempt) {
        if (make_quarantine_name(quarantine_name, sizeof(quarantine_name)) != 0) {
            break;
        }
        if (renameatx_np(parent_descriptor, argv[2], quarantine_descriptor,
                         quarantine_name, RENAME_EXCL) == 0) {
            renamed = true;
            break;
        }
        if (errno != EEXIST) {
            break;
        }
    }

    if (!renamed) {
        print_errno("rename-to-quarantine", argv[2]);
        close(quarantine_descriptor);
        close(parent_descriptor);
        return ExitRenameFailed;
    }

    struct stat quarantined;
    if (fstatat(quarantine_descriptor, quarantine_name, &quarantined,
                AT_SYMLINK_NOFOLLOW) != 0
        || !identity_matches(&quarantined, object_device, object_inode)) {
        fprintf(stderr,
                "installer_bound_delete_identity_mismatch=true\n"
                "installer_bound_delete_quarantine_entry=%s\n",
                quarantine_name);
        close(quarantine_descriptor);
        close(parent_descriptor);
        return ExitIdentityMismatch;
    }

    if (remove_entry_bound(quarantine_descriptor, quarantine_name) != 0) {
        print_errno("delete-quarantined-object", quarantine_name);
        close(quarantine_descriptor);
        close(parent_descriptor);
        return ExitDeleteFailed;
    }

    int quarantine_close_status = close(quarantine_descriptor);
    int parent_close_status = close(parent_descriptor);
    if (quarantine_close_status != 0 || parent_close_status != 0) {
        fputs("installer_bound_delete_error=close-directory-descriptor\n", stderr);
        return ExitDeleteFailed;
    }

    fputs("installer_bound_delete=deleted\n", stdout);
    return 0;
}
