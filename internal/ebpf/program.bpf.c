//go:build ignore

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#define TASK_COMM_LEN 	16
#define MAX_DENY_PATHS 	32
#define PATH_LEN 		256
#define EACCES 			13

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#ifndef BPF_MAP_TYPE_ARRAY
#define BPF_MAP_TYPE_ARRAY 2
#endif

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

#ifndef BPF_MAP_TYPE_CGROUP_ARRAY
#define BPF_MAP_TYPE_CGROUP_ARRAY 8
#endif

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

// struct path;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static long (*bpf_current_task_under_cgroup)(void *map, __u32 index) = (void *)37;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
// static long (*bpf_d_path)(struct path *path, char *buf, __u32 size) = (void *)147;

enum event_type {
	EVENT_EXEC = 1,
	EVENT_CONNECT,
	EVENT_OPEN,
};

// enum path_rule_type {
// 	RULE_PATH = 1,
// 	RULE_BASENAME
// };

struct event {
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 type;
	char comm[TASK_COMM_LEN];
	char data[PATH_LEN];
};

struct trace_event_raw_sys_enter {
	__u64 unused;
	__s32 id;
	__u64 args[6];
};

/*
 * Minimal CO-RE definitions. Clang records field relocations for f_path and
 * the loader resolves its real offset from the running kernel's BTF.
 */
// struct path {
// 	void *mnt;
// 	void *dentry;
// } __attribute__((preserve_access_index));

// struct file {
// 	struct path f_path;
// } __attribute__((preserve_access_index));

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
};

struct ipv6_address {
	__u32 words[4];
};

// struct path_rule {
// 	__u32 active;
// 	__u32 type;
// 	__u32 length;
// 	char value[PATH_LEN];
// };

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target_cgroup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} allowed_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct ipv6_address);
	__type(value, __u8);
} allowed_ipv6 SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, MAX_DENY_PATHS);
// 	__type(key, __u32);
// 	__type(value, struct path_rule);
// } deny_paths SEC(".maps");

static __always_inline int should_trace_current_process(void)
{
	return bpf_current_task_under_cgroup(&target_cgroup, 0) == 1;
}

static __always_inline struct event *reserve_event(__u32 type)
{
	struct event *evt;
	__u64 pid_tgid;
	__u64 uid_gid;

	if (!should_trace_current_process()) {
		return 0;
	}

	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt) {
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();

	evt->pid = (__u32)pid_tgid;
	evt->tgid = pid_tgid >> 32;
	evt->uid = (__u32)uid_gid;
	evt->type = type;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	return evt;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *evt;
	const char *filename;

	evt = reserve_event(EVENT_EXEC);
	if (!evt) {
		return 0;
	}

	filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(evt->data, sizeof(evt->data), filename);
	bpf_ringbuf_submit(evt, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct event *evt;

	evt = reserve_event(EVENT_CONNECT);
	if (!evt) {
		return 0;
	}

	evt->data[0] = '\0';
	bpf_ringbuf_submit(evt, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter  *ctx)
{
	struct event *evt;
	const char *filename;

	evt = reserve_event(EVENT_OPEN);
	if (!evt) {
		return 0;
	}

	filename = (const char *)ctx->args[1];
	bpf_probe_read_user_str(evt->data, sizeof(evt->data), filename);
	bpf_ringbuf_submit(evt, 0);

	return 0;
}

static __always_inline int is_ipv4_allowed(struct bpf_sock_addr *ctx)
{
	__u32 address = ctx->user_ip4;

	return bpf_map_lookup_elem(&allowed_ipv4, &address) != 0;
}

static __always_inline int is_ipv6_allowed(struct bpf_sock_addr *ctx)
{
	struct ipv6_address address = {};

	address.words[0] = ctx->user_ip6[0];
	address.words[1] = ctx->user_ip6[1];
	address.words[2] = ctx->user_ip6[2];
	address.words[3] = ctx->user_ip6[3];

	return bpf_map_lookup_elem(&allowed_ipv6, &address) != 0;
}

SEC("cgroup/connect4")
int enforce_connect4(struct bpf_sock_addr *ctx)
{
	return is_ipv4_allowed(ctx);
}

SEC("cgroup/connect6")
int enforce_connect6(struct bpf_sock_addr *ctx)
{
	return is_ipv6_allowed(ctx);
}

SEC("cgroup/sendmsg4")
int enforce_sendmsg4(struct bpf_sock_addr *ctx)
{
	return is_ipv4_allowed(ctx);
}

SEC("cgroup/sendmsg6")
int enforce_sendmsg6(struct bpf_sock_addr *ctx)
{
	return is_ipv6_allowed(ctx);
}

// static __always_inline int match_path_prefix(const char *path, const struct path_rule *rule)
// {
// 	__u32 length = rule->length;

// 	if (length == 0 || length >= PATH_LEN)
// 		return 0;

// 	/* Treat a configured trailing slash as the same directory path. */
// 	if (length > 1 && rule->value[length - 1] == '/')
// 		length--;

// 	for (__u32 i = 0; i < PATH_LEN; i++) {
// 		if (i >= length)
// 			break;
// 		if (path[i] != rule->value[i])
// 			return 0;
// 	}

// 	/* Match the exact path or a child, but not /secret-backup. */
// 	return path[length] == '\0' || path[length] == '/';
// }

// static __always_inline int match_basename(const char *path, const struct path_rule *rule)
// {
// 	__u32 path_length = 0;
// 	__u32 rule_length = rule->length;
// 	__u32 start;

// 	if (rule_length == 0 || rule_length >= PATH_LEN)
// 		return 0;

// 	for (__u32 i = 0; i < PATH_LEN; i++) {
// 		if (path[i] == '\0') {
// 			path_length = i;
// 			break;
// 		}
// 	}
// 	if (path_length == 0 || path_length < rule_length)
// 		return 0;

// 	start = path_length - rule_length;
// 	if (start > 0 && path[start - 1] != '/')
// 		return 0;

// 	for (__u32 i = 0; i < PATH_LEN; i++) {
// 		if (i >= rule_length)
// 			break;
// 		if (path[start + i] != rule->value[i])
// 			return 0;
// 	}

// 	return 1;
// }

// static __always_inline int path_matches_rule(const char *path, const struct path_rule *rule)
// {
// 	if (rule->type == RULE_PATH)
// 		return match_path_prefix(path, rule);
// 	if (rule->type == RULE_BASENAME)
// 		return match_basename(path, rule);
// 	return 0;
// }

// SEC("lsm/file_open")
// int enforce_file_open(__u64 *ctx)
// {
// 	struct file *file = (struct file *)ctx[0];
// 	int ret = (int)ctx[1];
// 	char path[PATH_LEN];

// 	if (ret != 0)
// 		return ret;

// 	/* LSM programs attach globally, so filter the container first. */
// 	if (bpf_current_task_under_cgroup(&target_cgroup, 0) != 1)
// 		return 0;

// 	if (bpf_d_path(&file->f_path, path, sizeof(path)) < 0)
// 		return 0;

// 	for (__u32 i = 0; i < MAX_DENY_PATHS; i++) {
// 		struct path_rule *rule;

// 		rule = bpf_map_lookup_elem(&deny_paths, &i);
// 		if (!rule || !rule->active)
// 			continue;

// 		if (path_matches_rule(path, rule))
// 			return -EACCES;
// 	}

// 	return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";
