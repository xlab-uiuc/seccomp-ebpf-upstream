#include <uapi/linux/seccomp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/unistd.h>
#include <uapi/linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <uapi/linux/audit.h>

#if defined(__x86_64__)
#define ARCH	AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define ARCH	AUDIT_ARCH_I386
#else
#endif

#ifdef ARCH
#define SIZ 256
SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	char buf[SIZ];

	if (ctx->arch != ARCH)
		return SECCOMP_RET_ERRNO | EPERM;

	if (ctx->nr == __NR_openat) {
		long res = bpf_probe_read_user_str(buf, sizeof(buf),
										   (void*)ctx->args[1]);
		if (res < 0)
			return res == -EPERM ? SECCOMP_RET_ERRNO | ENOSYS :
								   SECCOMP_RET_ERRNO | -res;
	}
	return SECCOMP_RET_ALLOW;
}
#else
#warning Architecture not supported -- Blocking all syscalls
SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	return SECCOMP_RET_ERRNO | EPERM;
}
#endif

char _license[] SEC("license") = "GPL";
