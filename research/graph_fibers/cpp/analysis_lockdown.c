#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

/* Applied before the analyzer's main(), or explicitly before a Python reader
 * opens the target. No target code is loaded. All errors are fail-closed. */
static void fatal(const char *what) {
    perror(what);
    _exit(125);
}
static void grant(int rules, const char *path, uint64_t access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        fatal(path);
    struct landlock_path_beneath_attr rule = {.allowed_access = access, .parent_fd = fd};
    if (syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &rule, 0))
        fatal("landlock_add_rule");
    close(fd);
}
#define DENY(n)                                                                                    \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (n), 0, 1),                                                \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
void analysis_lockdown(const char *input, const char *spec, const char *output) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) {
        errno = ENOTSUP;
        fatal("Landlock ABI >=3 required");
    }
    uint64_t handled = (1ULL << 15) - 1;
    if (abi >= 5)
        handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    struct landlock_ruleset_attr attr = {.handled_access_fs = handled};
    int rules = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (rules < 0)
        fatal("landlock_create_ruleset");
    grant(rules, input, LANDLOCK_ACCESS_FS_READ_FILE);
    if (spec && *spec) {
        struct stat st;
        if (stat(spec, &st))
            fatal(spec);
        grant(rules, spec,
              LANDLOCK_ACCESS_FS_READ_FILE |
                  (S_ISDIR(st.st_mode) ? LANDLOCK_ACCESS_FS_READ_DIR : 0));
    }
    const char *runtime = getenv("ANALYSIS_RUNTIME");
    if (runtime && *runtime)
        grant(rules, runtime, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
    grant(rules, output,
          LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
              LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG |
              LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_TRUNCATE |
              LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        fatal("no_new_privs");
    if (syscall(SYS_landlock_restrict_self, rules, 0))
        fatal("landlock_restrict_self");
    close(rules);
    /* Deny executable mappings after the trusted loader has initialized;
     * deny every exec, network socket, subprocess, namespace and ptrace call.
     * Z3's timer threads may use clone with CLONE_THREAD. */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        DENY(SYS_execve),
        DENY(SYS_execveat),
        DENY(SYS_socket),
        DENY(SYS_socketpair),
        DENY(SYS_connect),
        DENY(SYS_bind),
        DENY(SYS_listen),
        DENY(SYS_accept),
        DENY(SYS_accept4),
        DENY(SYS_fork),
        DENY(SYS_vfork),
        DENY(SYS_ptrace),
        DENY(SYS_process_vm_readv),
        DENY(SYS_process_vm_writev),
        DENY(SYS_mount),
        DENY(SYS_umount2),
        DENY(SYS_unshare),
        DENY(SYS_setns),
        DENY(SYS_bpf),
        DENY(SYS_perf_event_open),
        DENY(SYS_userfaultfd),
        DENY(SYS_io_uring_setup),
        DENY(SYS_memfd_create),
        DENY(SYS_open_by_handle_at),
        DENY(SYS_kill),
        DENY(SYS_pidfd_send_signal),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program))
        fatal("seccomp");
    struct rlimit core = {0, 0};
    setrlimit(RLIMIT_CORE, &core);
}
__attribute__((constructor)) static void preload_lockdown(void) {
    const char *input = getenv("ANALYSIS_INPUT"), *output = getenv("ANALYSIS_OUTPUT");
    if (input && output) {
        analysis_lockdown(input, getenv("ANALYSIS_SPEC"), output);
        const char *marker = getenv("ANALYSIS_MARKER");
        if (marker && *marker) {
            FILE *f = fopen(marker, "w");
            if (!f)
                fatal("sandbox marker");
            fputs("{\"landlock\":true,\"seccomp\":true,\"no_new_privs\":true}\n", f);
            if (fclose(f))
                fatal("sandbox marker close");
        }
    }
}
