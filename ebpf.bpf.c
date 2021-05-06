// SPDX-License-Identifier: GPL-2.0
#include <linux/sched.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/keyctl.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>

#include "config.h"

#if defined(__x86_64__)
#define ARCH	AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define ARCH	AUDIT_ARCH_I386
#else
#endif
#ifdef ARCH

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} syscall_state SEC(".maps");

SEC("seccomp")
int seccomp_filter(struct seccomp_data *ctx) {
	/*
	 * Make sure this BPF program is being run on the same architecture it
	 * was compiled on.
	 */
	if (unlikely(ctx->arch != ARCH))
		return SECCOMP_RET_ERRNO | EPERM;

	if (ctx->nr == __NR_getpid) {
		int *prev = bpf_task_storage_get(&syscall_state, NULL, NULL,
						 BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (unlikely(!prev))
			return SECCOMP_RET_KILL_PROCESS;
		// First time call
		if ((*prev)++ < N_CALL / 2) {
			return SECCOMP_RET_ALLOW;
		} else {
			return SECCOMP_RET_ERRNO | EPERM;
		}
	}

	return SECCOMP_RET_ALLOW;
}
#else
#warning Architecture not supported -- Blocking all syscalls
SEC("seccomp")
int seccomp_filter(struct seccomp_data *ctx)
{
	return SECCOMP_RET_ERRNO | EPERM;
}
#endif
char _license[] SEC("license") = "GPL";
