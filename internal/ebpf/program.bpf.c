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

#define TASK_COMM_LEN 16
#define PATH_LEN 256

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

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)114;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

enum event_type {
	EVENT_EXEC = 1,
	EVENT_CONNECT = 2,
	EVENT_OPEN = 3,
};

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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target_pid SEC(".maps");

static __always_inline int should_trace_current_process(void)
{
	__u32 key = 0;
	__u32 *target;
	__u64 pid_tgid;
	__u32 tgid;

	target = bpf_map_lookup_elem(&target_pid, &key);
	if (!target || *target == 0) {
		return 1;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = pid_tgid >> 32;

	return tgid == *target;
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
