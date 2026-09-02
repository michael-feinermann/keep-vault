#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

enum { mapped_descriptor = 73 };

static int wait_for_success(pid_t child) {
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return 1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int spawn_with_mapped_descriptor(
    const char *executable,
    char *const argv[],
    int source_descriptor) {
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) return 1;
    int result = posix_spawn_file_actions_adddup2(
        &actions,
        source_descriptor,
        mapped_descriptor);
    pid_t child = -1;
    if (result == 0) {
        char *const empty_environment[] = { NULL };
        result = posix_spawn(
            &child,
            executable,
            &actions,
            NULL,
            argv,
            empty_environment);
    }
    const int destroy_result = posix_spawn_file_actions_destroy(&actions);
    if (result != 0 || destroy_result != 0) return 1;
    return wait_for_success(child);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--self-check-fd") == 0) {
        char *end = NULL;
        errno = 0;
        long descriptor = strtol(argv[2], &end, 10);
        if (errno != 0 || end == argv[2] || *end != '\0'
            || descriptor != mapped_descriptor
            || fcntl((int)descriptor, F_GETFD) < 0) {
            return 77;
        }
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "--zpaq") != 0
        || argv[2][0] != '/') {
        return 64;
    }

    char temporary[] = "/private/tmp/keep-vault-zpaq-fd-harness.XXXXXX";
    int source_descriptor = mkstemp(temporary);
    if (source_descriptor < 0 || unlink(temporary) != 0) return 1;
    if (fcntl(source_descriptor, F_SETFD, 0) != 0) {
        close(source_descriptor);
        return 1;
    }

    char mapped_text[16];
    if (snprintf(mapped_text, sizeof(mapped_text), "%d", mapped_descriptor) <= 0) {
        close(source_descriptor);
        return 1;
    }
    char *const self_argv[] = {
        argv[0],
        "--self-check-fd",
        mapped_text,
        NULL,
    };
    if (spawn_with_mapped_descriptor(argv[0], self_argv, source_descriptor) != 0) {
        close(source_descriptor);
        return 78;
    }

    char *const zpaq_argv[] = {
        argv[2],
        "--keepvault-inherited-fd-guard-canary",
        mapped_text,
        NULL,
    };
    int result = spawn_with_mapped_descriptor(
        argv[2],
        zpaq_argv,
        source_descriptor);
    if (close(source_descriptor) != 0 && result == 0) result = 1;
    return result;
}
