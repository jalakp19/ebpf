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
} __attribute__((preserve_access_index));

/**
 * struct tcp_sock is the Linux representation of a TCP socket.
 * This is a simplified copy of the kernel's struct tcp_sock.
 * For this example we only need srtt_us to read the smoothed RTT.
 */
struct tcp_sock {
	u32 srtt_us;
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