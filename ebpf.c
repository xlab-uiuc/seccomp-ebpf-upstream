// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/keyctl.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "ebpf.skel.h"
#include "config.h"
#include "payload.h"

int main(int argc, char **argv)
{
	struct ebpf_bpf *obj;
	int prog_fd;

	obj = ebpf_bpf__open_and_load();
	if (!obj)
		exit(1);

	prog_fd = bpf_program__fd(obj->progs.seccomp_filter);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(prog_fd));
		exit(1);
	}

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(1);
	}

	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
		    SECCOMP_FILTER_FLAG_EXTENDED, &prog_fd)) {
		perror("seccomp");
		exit(1);
	}

	payload();

	return 0;
}
