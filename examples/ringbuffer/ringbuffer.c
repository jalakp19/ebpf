// +build ignore

// #include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common.h"

#include "bpf_endian.h"

#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

// For SIP messages
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

/**
 * For CO-RE relocatable eBPF programs, __attribute__((preserve_access_index))
 * preserves the offset of the specified fields in the original kernel struct.
 * So here we don't need to include "vmlinux.h". Instead we only need to define
 * the kernel struct and their fields the eBPF program actually requires.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common is the minimal network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock_common.
 * This copy contains only the fields needed for this example to
 * fetch the source and destination port numbers and IP addresses.
 */

struct sock_common {
	union {
		struct {
			// skc_daddr is destination IP address
			__be32 skc_daddr;
			// skc_rcv_saddr is the source IP address
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			// skc_dport is the destination TCP/UDP port
			__be16 skc_dport;
			// skc_num is the source TCP/UDP port
			__u16 skc_num;
		};
	};
	volatile unsigned char skc_state;
	// skc_family is the network address family (2 for IPV4)
	short unsigned int skc_family;
} __attribute__((preserve_access_index));

/**
 * struct sock is the network layer representation of sockets.
 * This is a simplified copy of the kernel's struct sock.
 * This copy is needed only to access struct sock_common.
 */
struct sock {
	struct sock_common __sk_common;
	int sk_rcvbuf;
	int sk_sndbuf;
} __attribute__((preserve_access_index));

/**
 * struct tcp_sock is the Linux representation of a TCP socket.
 * This is a simplified copy of the kernel's struct tcp_sock.
 * For this example we only need srtt_us to read the smoothed RTT.
 */
struct tcp_sock {
	u32 srtt_us;
	u32 rcv_nxt;
	u32 snd_una;
	u32 write_seq;
	u32 copied_seq;
} __attribute__((preserve_access_index));

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */

// For TCP RTT
struct tcpevent {
	u8 comm[80];
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
	u32 srtt;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} tcpevents SEC(".maps");

const struct tcpevent *unused2 __attribute__((unused));

// For TCP latency
struct latdata {
	u8 comm[80];
	u64 delta_us;
	u64 ts_us;
	u16 sport;
	u16 dport;
	u32 saddr;
	u32 daddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} latdatas SEC(".maps");

const struct latdata *unusedld __attribute__((unused));

struct piddata {
	u8 comm[80];
	u64 ts;
	u32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} piddatas SEC(".maps");

const struct piddata *unusedp __attribute__((unused));

struct bpf_map_def SEC("maps") start = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct sock *),
	.value_size  = sizeof(struct piddata),
	.max_entries = 4096,
};

// Kernel read write buffer usage percentage

static inline struct tcp_sock *tcp_sk(const struct sock *sk) {
	return (struct tcp_sock *)sk;
}

struct stats_key {
	char cgroup_name[129];
};

struct stats_value {
	__u32 read_buffer_max_usage;
	__u32 write_buffer_max_usage;
};

/*
 * The `tcp_queue_stats` map is used to share with the userland program system-probe
 * the statistics (max size of receive/send buffer)
 */

struct bpf_map_def SEC("maps") tcp_queue_stats = {
	.type        = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size    = sizeof(struct stats_key),
	.value_size  = sizeof(struct stats_value),
	.max_entries = 1024,
};

/*
 * the `who_recvmsg` and `who_sendmsg` maps are used to remind the sock pointer
 * received as input parameter when we are in the kretprobe of tcp_recvmsg and tcp_sendmsg.
 */
struct bpf_map_def SEC("maps") who_recvmsg = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(struct sock *),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps") who_sendmsg = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(struct sock *),
	.max_entries = 128,
};

struct queuedata {
	u8 comm[80];
	u32 read_buffer_max_usage;
	u32 write_buffer_max_usage;
	u64 rqueue_size;
	u64 wqueue_size;
	u64 rqueue;
	u64 wqueue;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} queuedatas SEC(".maps");

const struct queuedata *unusedq __attribute__((unused));

extern void *memset();

struct task_struct {
	struct css_set *cgroups;
};

struct css_set {
	struct cgroup_subsys_state *subsys[2];
};

struct cgroup_subsys_state {
	struct cgroup *cgroup;
};

struct cgroup {
	struct kernfs_node *kn;
};

struct kernfs_node {
	char *name;
};

static int get_cgroup_name(char *buf, int sz) {
	memset(buf, 0, sz);

	struct task_struct *cur_tsk = (struct task_struct *)bpf_get_current_task();

	struct css_set *css_set;
	if (bpf_probe_read(&css_set, sizeof(css_set), &cur_tsk->cgroups) < 0)
		return -1;

	struct cgroup_subsys_state *css;
	if (bpf_probe_read(&css, sizeof(css), &css_set->subsys[0]) < 0)
		return -1;

	struct cgroup *cgrp;
	if (bpf_probe_read(&cgrp, sizeof(cgrp), &css->cgroup) < 0)
		return -1;

	struct kernfs_node *kn;
	if (bpf_probe_read(&kn, sizeof(kn), &cgrp->kn) < 0)
		return -1;

	const char *name;
	if (bpf_probe_read(&name, sizeof(name), &kn->name) < 0)
		return -1;

	if (bpf_probe_read_str(buf, sz, (void *)name) < 0)
		return -1;

	return 0;
}

// TODO: replace all `bpf_probe_read` by `bpf_probe_read_kernel` once we can assume that we have at least kernel 5.5
static int check_sock(struct pt_regs *ctx, struct sock *sk) {
	struct stats_value zero = {.read_buffer_max_usage = 0, .write_buffer_max_usage = 0};

	struct stats_key k;
	get_cgroup_name(k.cgroup_name, sizeof(k.cgroup_name));

	bpf_map_update_elem(&tcp_queue_stats, &k, &zero, BPF_NOEXIST);
	struct stats_value *v = bpf_map_lookup_elem(&tcp_queue_stats, &k);
	if (!v) {
		return 0;
	}

	int rqueue_size, wqueue_size;
	bpf_probe_read(&rqueue_size, sizeof(rqueue_size), (void *)&sk->sk_rcvbuf);
	bpf_probe_read(&wqueue_size, sizeof(wqueue_size), (void *)&sk->sk_sndbuf);

	const struct tcp_sock *tp = tcp_sk(sk);
	u32 rcv_nxt, copied_seq, write_seq, snd_una;
	bpf_probe_read(&rcv_nxt, sizeof(rcv_nxt), (void *)&tp->rcv_nxt);          // What we want to receive next
	bpf_probe_read(&copied_seq, sizeof(copied_seq), (void *)&tp->copied_seq); // Head of yet unread data
	bpf_probe_read(&write_seq, sizeof(write_seq), (void *)&tp->write_seq);    // Tail(+1) of data held in tcp send buffer
	bpf_probe_read(&snd_una, sizeof(snd_una), (void *)&tp->snd_una);          // First byte we want an ack for

	u32 rqueue = rcv_nxt < copied_seq ? 0 : rcv_nxt - copied_seq;
	if (rqueue < 0)
		rqueue = 0;
	u32 wqueue = write_seq - snd_una;

	u32 rqueue_usage = 1000 * rqueue / rqueue_size;
	u32 wqueue_usage = 1000 * wqueue / wqueue_size;

	if (rqueue_usage > v->read_buffer_max_usage)
		v->read_buffer_max_usage = rqueue_usage;
	if (wqueue_usage > v->write_buffer_max_usage)
		v->write_buffer_max_usage = wqueue_usage;

	struct queuedata qd = {};
	bpf_get_current_comm(&qd.comm, 80);
	qd.read_buffer_max_usage  = v->read_buffer_max_usage;
	qd.write_buffer_max_usage = v->write_buffer_max_usage;
	qd.rqueue_size            = rqueue_size;
	qd.wqueue_size            = wqueue_size;
	qd.rqueue                 = rqueue;
	qd.wqueue                 = wqueue;

	bpf_perf_event_output(ctx, &queuedatas, BPF_F_CURRENT_CPU, &qd, sizeof(qd));

	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg) {
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u64 pid_tgid    = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&who_recvmsg, &pid_tgid, &sk, BPF_ANY);

	return check_sock(ctx, sk);
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcprecvmsg(struct pt_regs *ctx) {
	u64 pid_tgid     = bpf_get_current_pid_tgid();
	struct sock **sk = bpf_map_lookup_elem(&who_recvmsg, &pid_tgid);
	bpf_map_delete_elem(&who_recvmsg, &pid_tgid);

	if (sk)
		return check_sock(ctx, *sk);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg) {
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u64 pid_tgid    = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&who_sendmsg, &pid_tgid, &sk, BPF_ANY);

	return check_sock(ctx, sk);
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcpsendmsg(struct pt_regs *ctx) {
	u64 pid_tgid     = bpf_get_current_pid_tgid();
	struct sock **sk = bpf_map_lookup_elem(&who_sendmsg, &pid_tgid);
	bpf_map_delete_elem(&who_sendmsg, &pid_tgid);

	if (sk)
		return check_sock(ctx, *sk);
	return 0;
}

// TCP Latency

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk) {
	u32 tgid               = bpf_get_current_pid_tgid() >> 32;
	struct piddata piddata = {};

	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
	piddata.ts   = bpf_ktime_get_ns();
	piddata.tgid = tgid;
	bpf_map_update_elem(&start, &sk, &piddata, BPF_ANY);

	return 0;
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk) {
	struct piddata *pd = bpf_map_lookup_elem(&start, &sk);
	if (!pd)
		return 0;

	struct latdata ld = {};
	s64 delta;
	u64 ts;

	ts    = bpf_ktime_get_ns();
	delta = (s64)(ts - pd->ts);
	if (delta < 0) {
		bpf_map_delete_elem(&start, &sk);
		return 0;
	}

	bpf_get_current_comm(&ld.comm, 80);
	ld.delta_us = delta / 1000;
	ld.ts_us    = ts / 1000;

	bpf_probe_read(&ld.dport, sizeof(ld.dport), &sk->__sk_common.skc_dport);
	ld.dport = bpf_ntohs(ld.dport);
	bpf_probe_read(&ld.sport, sizeof(ld.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&ld.saddr, sizeof(ld.saddr), &sk->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&ld.daddr, sizeof(ld.daddr), &sk->__sk_common.skc_daddr);

	bpf_perf_event_output(ctx, &latdatas, BPF_F_CURRENT_CPU, &ld, sizeof(ld));

	bpf_map_delete_elem(&start, &sk);
	return 0;
}

// If this code is run on a server, then sendto will send 180 Ringing, 200 OK, 200 OK
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

// If this code is run on a server, then recvfrom will receive Invite, Ack, Bye
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

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	// The input struct sock is actually a tcp_sock, so we can type-cast
	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
	if (!ts) {
		return 0;
	}

	struct tcpevent *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&tcpevents, sizeof(struct tcpevent), 0);
	if (!tcp_info) {
		return 0;
	}

	bpf_get_current_comm(&tcp_info->comm, 80);

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	tcp_info->sport = sk->__sk_common.skc_num;

	tcp_info->srtt = ts->srtt_us >> 3;
	// tcp_info->srtt /= 1000;

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}