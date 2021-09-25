#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <bpf/libbpf.h>

static void install_seccomp(char *filename)
{
	int prog_fd;
	struct bpf_object *obj;

	if (bpf_prog_load(filename, BPF_PROG_TYPE_SECCOMP, &obj, &prog_fd))
		exit(EXIT_FAILURE);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n", strerror(prog_fd));
		exit(EXIT_FAILURE);
	}

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(EXIT_FAILURE);
	}

	if ((prog_fd = dup(prog_fd)) < 0) {
		perror("dup(prog_fd)");
		exit(EXIT_FAILURE);
	}

	bpf_object__close(obj);

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
		    SECCOMP_FILTER_FLAG_EXTENDED, &prog_fd)) {
		perror("seccomp");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	pid_t pid;
	char filename[120];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	// enter a new pid ns
	if (unshare(CLONE_NEWPID) < 0) {
		perror("unshare(CLONE_NEWPID)");
		return 1;
	}

	pid = fork();

	if (pid < 0) {
		perror("fork");
		return 1;
	} else if (pid == 0) { // child
		install_seccomp(filename);
		pid = getpid();
		fprintf(stdout, "Inside new pidns: pid=%d\n", pid);
	} else { // parent
		int wstatus;
		fprintf(stdout, "Outside new pidns: pid=%d\n", pid);
		waitpid(-1, &wstatus, 0);
	}

	return 0;
}
