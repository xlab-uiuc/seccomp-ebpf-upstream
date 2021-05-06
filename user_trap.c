#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "config.h"
#include "payload.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
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

static int user_trap_syscall(int nr, unsigned int flags)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};

	return seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
}

static int handle_req(struct seccomp_notif *req,
		      struct seccomp_notif_resp *resp, int listener)
{
	static int count = 0;

	resp->id = req->id;
	resp->error = -EPERM;
	resp->val = 0;
	resp->flags = 0;

	if (unlikely(req->data.nr != __NR_getpid)) {
		fprintf(stderr, "huh? trapped something besides getpid? %d\n", req->data.nr);
		return -1;
	}

	if (count++ < N_CALL / 2) {
		resp->error = 0;
		resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	}

	return 0;
}

int main(void)
{
	int sk_pair[2], ret = 1, status, listener;
	pid_t worker = 0 , tracer = 0;

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sk_pair) < 0) {
		perror("socketpair");
		return 1;
	}

	/* set new_new_privs so non-privileged users can attach filters */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		goto close_pair;
	}

	worker = fork();
	if (worker < 0) {
		perror("fork");
		goto close_pair;
	}

	if (worker == 0) {
		listener = user_trap_syscall(__NR_getpid,
					     SECCOMP_FILTER_FLAG_NEW_LISTENER);
		if (listener < 0) {
			perror("seccomp");
			exit(1);
		}

		/*
		 * Send the listener to the parent; also serves as
		 * synchronization.
		 */
		if (send_fd(sk_pair[1], listener) < 0)
			exit(1);
		close(listener);

		payload();

		exit(0);
	}

	/*
	 * Get the listener from the child.
	 */
	listener = recv_fd(sk_pair[0]);
	if (listener < 0)
		goto out_kill;

	/*
	 * Fork a task to handle the requests. This isn't strictly necessary,
	 * but it makes the particular writing of this sample easier, since we
	 * can just wait ofr the tracee to exit and kill the tracer.
	 */
	tracer = fork();
	if (tracer < 0) {
		perror("fork");
		goto out_kill;
	}

	if (tracer == 0) {
		struct seccomp_notif *req;
		struct seccomp_notif_resp *resp;
		struct seccomp_notif_sizes sizes;

		if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
			perror("seccomp(GET_NOTIF_SIZES)");
			goto out_close;
		}

		req = malloc(sizes.seccomp_notif);
		if (!req)
			goto out_close;

		resp = malloc(sizes.seccomp_notif_resp);
		if (!resp)
			goto out_req;
		memset(resp, 0, sizes.seccomp_notif_resp);

		while (1) {
			memset(req, 0, sizes.seccomp_notif);
			if (unlikely(ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req))) {
				perror("ioctl recv");
				goto out_resp;
			}

			if (unlikely(handle_req(req, resp, listener) < 0))
				goto out_resp;

			/*
			 * ENOENT here means that the task may have gotten a
			 * signal and restarted the syscall. It's up to the
			 * handler to decide what to do in this case, but for
			 * the sample code, we just ignore it. Probably
			 * something better should happen, like undoing the
			 * mount, or keeping track of the args to make sure we
			 * don't do it again.
			 */
			if (unlikely(ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) &&
			    errno != ENOENT) {
				perror("ioctl send");
				goto out_resp;
			}
		}
out_resp:
		free(resp);
out_req:
		free(req);
out_close:
		close(listener);
		exit(1);
	}

	close(listener);

	if (waitpid(worker, &status, 0) != worker) {
		perror("waitpid");
		goto out_kill;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "worker exited nonzero\n");
		goto out_kill;
	}

	ret = 0;

out_kill:
	if (tracer > 0)
		kill(tracer, SIGKILL);
	if (worker > 0)
		kill(worker, SIGKILL);

close_pair:
	close(sk_pair[0]);
	close(sk_pair[1]);
	return ret;
}
