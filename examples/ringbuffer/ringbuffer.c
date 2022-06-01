// +build ignore

#include "bpf_tracing.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];
	u32 fd;
	u32 len;
	u8 msg[500];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("kprobe/__sys_sendto")
int kprobe_sendto(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *sm;

	sm = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!sm) {
		return 0;
	}

	bpf_get_current_comm(&sm->comm, 80);

	sm->pid = tgid;
	sm->fd  = (int)(PT_REGS_PARM1(ctx));
	sm->len = (int)(PT_REGS_PARM3(ctx));

	void *buff = (void *)(PT_REGS_PARM2(ctx));

	bpf_probe_read_str(&sm->msg, sizeof(sm->msg), (void *)buff);

	bpf_ringbuf_submit(sm, 0);

	return 0;
}

SEC("kprobe/__sys_recvfrom")
int kprobe_recvfrom(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *sm;

	sm = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!sm) {
		return 0;
	}

	bpf_get_current_comm(&sm->comm, 80);

	sm->pid = tgid;
	sm->fd  = (int)(PT_REGS_PARM1(ctx));
	sm->len = (int)(PT_REGS_PARM3(ctx));

	void *buff = (void *)(PT_REGS_PARM2(ctx));

	bpf_probe_read_str(&sm->msg, sizeof(sm->msg), (void *)buff);

	bpf_ringbuf_submit(sm, 0);

	return 0;
}
