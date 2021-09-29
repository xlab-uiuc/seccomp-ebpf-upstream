#include <uapi/linux/audit.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/errno.h>
#include <uapi/linux/seccomp.h>
#include <uapi/linux/unistd.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, long);
	__uint(max_entries, 1024);
} policy SEC(".maps");

SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	long key = ctx->nr, *val;
	val = bpf_map_lookup_elem(&policy, &key);
	return val ? *val : (SECCOMP_RET_ERRNO | EPERM);
}
