#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	return syscall(__NR_seccomp, op, flags, args);
}

static int send_fd(int sock, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*((int *)CMSG_DATA(cmsg)) = fd;
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(sock, &msg, 0) < 0) {
		perror("sendmsg");
		return -1;
	}

	return 0;
}

static int recv_fd(int sock)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))] = {0}, c = 'c';
	struct iovec io = {
		.iov_base = &c,
		.iov_len = 1,
	};

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	if (recvmsg(sock, &msg, 0) < 0) {
		perror("recvmsg");
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);

	return *((int *)CMSG_DATA(cmsg));
}

static int load_filter(const char * path)
{
	struct bpf_object *obj;
	char filename[256];
	int prog_fd;
	int new_prog_fd;

	snprintf(filename, sizeof(filename), "%s_kern.o", path);

	if (bpf_prog_load(filename, BPF_PROG_TYPE_SECCOMP, &obj, &prog_fd))
		return -1;
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(prog_fd));
		return -1;
	}

	if ((new_prog_fd = dup(prog_fd)) < 0) {
		perror("dup(prog_fd)");
		return -1;
	}

	bpf_object__close(obj);

	return new_prog_fd;
}

int main(int argc, const char *argv[])
{
	int sk_pair[2];
	int worker;
	int filter;
	int self;

	if (setuid(1000)) {
		perror("setuid");
		return 1;
	}

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair) < 0) {
		perror("socketpair");
		return 1;
	}

	worker = fork();

	if (worker == 0) {
		if (unshare(CLONE_NEWUSER)) {
			perror("child unshare");
			exit(1);
		}

		if ((filter = load_filter(argv[0])) < 0)
			exit(1);

		if (send_fd(sk_pair[1], filter) < 0)
			exit(1);

		close(filter);
		exit(0);
	}
	filter = recv_fd(sk_pair[0]);

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		return 1;
	}

	if (seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_EXTENDED,
		 		&filter)) {
		perror("seccomp");
		return 1;
	}

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
		perror("prctl(PR_SET_DUMPABLE)");
		return 1;
	}

	if ((self = open(argv[0], O_RDONLY)) < 0) {
		perror("open");
		return 1;
	}

	close(self);
	return 0;
}
