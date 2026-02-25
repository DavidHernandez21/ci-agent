#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "ci-agent.h"

/* Socket address families */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* IP protocols */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Ethernet protocol types */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Map to store IP -> hostname mappings from DNS responses */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dns_mapping_key);
	__type(value, struct dns_mapping_value);
} dns_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bpf_filter_config);
} filter_config_map SEC(".maps");

static __always_inline void fill_network_info(struct event *e, struct sock *sk, size_t size)
{
	struct inet_sock *inet = (struct inet_sock *)sk;
	__u16 family;
	__be32 saddr4, daddr4;
	__be16 sport, dport;
	
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->family = family;
	e->bytes_sent = size;
	
	if (family == AF_INET) {
		/* IPv4 */
		saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		sport = BPF_CORE_READ(inet, inet_sport);
		dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		
		e->saddr[0] = bpf_ntohl(saddr4);
		e->daddr[0] = bpf_ntohl(daddr4);
		e->sport = bpf_ntohs(sport);
		e->dport = bpf_ntohs(dport);
		
		/* Clear IPv6 fields */
		e->saddr[1] = 0;
		e->saddr[2] = 0;
		e->saddr[3] = 0;
		e->daddr[1] = 0;
		e->daddr[2] = 0;
		e->daddr[3] = 0;
	} else if (family == AF_INET6) {
		/* IPv6 */
		sport = BPF_CORE_READ(inet, inet_sport);
		dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		
		/* Read IPv6 addresses - they're stored as 4 u32 words */
		bpf_core_read(&e->saddr[0], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
		bpf_core_read(&e->saddr[1], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[1]);
		bpf_core_read(&e->saddr[2], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
		bpf_core_read(&e->saddr[3], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
		
		bpf_core_read(&e->daddr[0], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
		bpf_core_read(&e->daddr[1], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[1]);
		bpf_core_read(&e->daddr[2], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
		bpf_core_read(&e->daddr[3], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);
		
		e->sport = bpf_ntohs(sport);
		e->dport = bpf_ntohs(dport);
	}
}

static __always_inline int is_loopback_v4(__u32 addr)
{
	/* addr is host-order __u32 (output of bpf_ntohl()). */
	return (addr & 0xff000000) == 0x7f000000;
}

static __always_inline int is_loopback_v6(const __u32 *addr)
{
	return addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && bpf_ntohl(addr[3]) == 1;
}

static __always_inline int match_ip_filter_bpf(const struct bpf_ip_filter *f,
				      const struct event *e,
				      int is_src)
{
	if (!f || !f->set)
		return 1;

	if (f->loopback) {
		if (e->family == AF_INET) {
			__u32 addr = is_src ? e->saddr[0] : e->daddr[0];
			return is_loopback_v4(addr);
		}
		if (e->family == AF_INET6) {
			const __u32 *addr = is_src ? e->saddr : e->daddr;
			return is_loopback_v6(addr);
		}

		return 0;
	}

	if (e->family != f->family)
		return 0;

	if (f->family == AF_INET) {
		return is_src ? (e->saddr[0] == f->addr[0])
			      : (e->daddr[0] == f->addr[0]);
	}

	/* IPv6 words are stored in network byte order on both sides; compare raw. */
	if (is_src) {
		return e->saddr[0] == f->addr[0] &&
		       e->saddr[1] == f->addr[1] &&
		       e->saddr[2] == f->addr[2] &&
		       e->saddr[3] == f->addr[3];
	}

	return e->daddr[0] == f->addr[0] &&
	       e->daddr[1] == f->addr[1] &&
	       e->daddr[2] == f->addr[2] &&
	       e->daddr[3] == f->addr[3];
}

static __always_inline int filter_event(const struct bpf_filter_config *cfg,
					      const struct event *net,
					      __u32 pid,
					      __u32 type)
{
	if (!cfg)
		return 1;

	if (cfg->has_pid && pid != cfg->pid)
		return 0;
	if (cfg->has_proto && cfg->type != type)
		return 0;
	if (net->family == AF_INET && cfg->exclude_local_src && is_loopback_v4(net->saddr[0]))
		return 0;
	if (net->family == AF_INET6 && cfg->exclude_local_src && is_loopback_v6(net->saddr))
		return 0;
	if (net->family == AF_INET && cfg->exclude_local_dst && is_loopback_v4(net->daddr[0]))
		return 0;
	if (net->family == AF_INET6 && cfg->exclude_local_dst && is_loopback_v6(net->daddr))
		return 0;
	if (!match_ip_filter_bpf(&cfg->src, net, 1))
		return 0;
	if (!match_ip_filter_bpf(&cfg->dst, net, 0))
		return 0;
	if (cfg->exclude_port_count) {
		for (int i = 0; i < MAX_EXCLUDE_PORTS; i++) {
			if (i >= cfg->exclude_port_count)
				break;
			if (net->sport == cfg->exclude_ports[i] || net->dport == cfg->exclude_ports[i])
				return 0;
		}
	}

	return 1;
}

static __always_inline void copy_network_fields(struct event *dst, const struct event *src)
{
	dst->family = src->family;
	dst->sport = src->sport;
	dst->dport = src->dport;
	__builtin_memcpy(dst->saddr, src->saddr, sizeof(dst->saddr));
	__builtin_memcpy(dst->daddr, src->daddr, sizeof(dst->daddr));
	dst->bytes_sent = src->bytes_sent;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_tcp_sendmsg,
	     struct sock *sk,
	     struct msghdr *msg,
	     size_t size)
{
	struct bpf_filter_config *cfg;
	__u32 cfg_key = 0;
	__u32 pid;
	struct event temp_event = {};

	if (!sk)
		return 0;

	cfg = bpf_map_lookup_elem(&filter_config_map, &cfg_key);
	pid = bpf_get_current_pid_tgid() >> 32;

	fill_network_info(&temp_event, sk, size);
	if (!filter_event(cfg, &temp_event, pid, EV_TCP_EGRESS))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EV_TCP_EGRESS;
	e->ts_nsec = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->protocol = IPPROTO_TCP;

	copy_network_fields(e, &temp_event);
	
	/* Look up hostname from DNS map */
	struct dns_mapping_key dns_key = {0};
	if (e->family == AF_INET) {
		dns_key.ip[0] = e->daddr[0];
		dns_key.family = AF_INET;
	} else if (e->family == AF_INET6) {
		dns_key.ip[0] = e->daddr[0];
		dns_key.ip[1] = e->daddr[1];
		dns_key.ip[2] = e->daddr[2];
		dns_key.ip[3] = e->daddr[3];
		dns_key.family = AF_INET6;
	}
	
	/* Note: We can't store hostname in event struct directly in BPF */
	/* Userspace will look it up from the map */
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* DNS capture is done in userspace (ci-agentd-dns.c) */
/* The DNS map is populated by userspace and read by BPF hooks below */

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg,
	     struct sock *sk,
	     struct msghdr *msg,
	     size_t len)
{
	struct bpf_filter_config *cfg;
	__u32 cfg_key = 0;
	__u32 pid;
	struct event temp_event = {};

	if (!sk)
		return 0;

	cfg = bpf_map_lookup_elem(&filter_config_map, &cfg_key);
	pid = bpf_get_current_pid_tgid() >> 32;

	fill_network_info(&temp_event, sk, len);
	if (!filter_event(cfg, &temp_event, pid, EV_UDP_EGRESS))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EV_UDP_EGRESS;
	e->ts_nsec = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->protocol = IPPROTO_UDP;

	copy_network_fields(e, &temp_event);
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}
