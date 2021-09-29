#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define SECCOMP_POLICY(nr, action)  \
do {    \
    long key = __NR_##nr, val = action;    \
    bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);  \
} while(0)

static void populate_map(int map_fd)
{
	SECCOMP_POLICY(exit_group, SECCOMP_RET_ALLOW);
}

static void install_seccomp(char *filename)
{
	int prog_fd, map_fd;
	struct bpf_object *obj;

	if (bpf_prog_load(filename, BPF_PROG_TYPE_SECCOMP, &obj, &prog_fd))
		exit(EXIT_FAILURE);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n", strerror(prog_fd));
		exit(EXIT_FAILURE);
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "policy");
	if (map_fd < 0) {
		perror("bpf_object__find_map_fd_by_name");
		exit(EXIT_FAILURE);
	}
	populate_map(map_fd);


	if ((prog_fd = dup(prog_fd)) < 0) {
		perror("dup(prog_fd)");
		exit(EXIT_FAILURE);
	}

	bpf_object__close(obj);

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(EXIT_FAILURE);
	}

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
		    SECCOMP_FILTER_FLAG_EXTENDED, &prog_fd)) {
		perror("seccomp");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else if (pid == 0) { // child
		char filename[120];
		volatile int i = 0;

		snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
		install_seccomp(filename);

		for (; i < INT_MAX; i++);
		exit(0);
	} else { // parent
		int wstatus, prog_fd, map_fd;
		sleep(1);
		if (syscall(__NR_ptrace, PTRACE_ATTACH, pid, NULL, NULL) < 0) {
			perror("ptrace attach");
			exit(0);
		}
		waitpid(pid, &wstatus, 0);
		fprintf(stderr, "ptrace attached\n");
		prog_fd = syscall(__NR_ptrace, PTRACE_SECCOMP_GET_FILTER_EXTENDED,
						 pid, (void *)0, NULL);
		if (prog_fd < 0) {
			perror("ptrace(PTRACE_SECCOMP_GET_FILTER_EXTENDED)");
			goto cleanup;
		}
		map_fd = syscall(__NR_ptrace, PTRACE_SECCOMP_GET_MAP_EXTENDED,
			 			pid, (void *)0, (void *)0);
		if (prog_fd < 0) {
			perror("ptrace(PTRACE_SECCOMP_GET_MAP_EXTENDED)");
			goto cleanup;
		}
		fprintf(stderr, "prog_fd=%d, map_fd=%d\n", prog_fd, map_fd);

cleanup:
		syscall(__NR_ptrace, PTRACE_CONT, pid, NULL, NULL);
		waitpid(pid, &wstatus, 0);
		fprintf(stderr, "child(%d) exited\n", pid);
		exit(0);
	}
}
