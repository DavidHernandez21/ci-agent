#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "ci-agent.h"
#include "ci-agent.skel.h"
#include "ci-agentd-broadcast.h"
#include "ci-agentd-dns.h"

enum fd_tag {
	FD_RINGBUF = 1,
	FD_LISTENER = 2,
};

enum summary_sort_by {
	SUMMARY_SORT_COUNT = 0,
	SUMMARY_SORT_BYTES = 1,
};

static volatile sig_atomic_t stop;

struct ip_filter {
	bool set;
	bool loopback;
	__u8 family;
	__u32 addr[4];
};

struct event_filter {
	bool has_pid;
	__u32 pid;
	bool has_proto;
	__u32 type;
	bool has_exe;
	char exe[PATH_MAX];
	struct ip_filter src;
	struct ip_filter dst;
	bool exclude_local_src;
	bool exclude_local_dst;
	__u16 exclude_ports[MAX_EXCLUDE_PORTS];
	size_t exclude_port_count;
};

static void sigint_handler(int signo)
{
	(void) signo;
	stop = 1;
}

static void print_usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\n"
		"Options:\n"
		"  -p, --pid <pid>         Match process id\n"
		"  -P, --proto <tcp|udp>   Match protocol\n"
		"  -e, --exe <string>      Substring match on executable path/comm (case-insensitive)\n"
		"  -s, --src <ip>          Match source IP (IPv4/IPv6) or 'local' for loopback\n"
		"  -d, --dst <ip>          Match destination IP (IPv4/IPv6) or 'local' for loopback\n"
		"  -x, --no-port <port>    Exclude events with source or destination port\n"
		"  -S, --summarize <dur>   Run for duration and emit a summary (e.g., 10s, 500ms, 2m)\n"
		"  -o, --sort-by <key>     Summary sort key with --summarize: count|bytes (default: count)\n"
		"      --no-local-src      Exclude loopback as source (127.0.0.0/8, ::1)\n"
		"      --no-local-dst      Exclude loopback as destination (127.0.0.0/8, ::1)\n"
		"  -h, --help              Show this help\n",
		argv0);
}

static int parse_proto(const char *s, __u32 *out_type)
{
	if (s == NULL || out_type == NULL)
		return -EINVAL;

	if (strcasecmp(s, "tcp") == 0) {
		*out_type = EV_TCP_EGRESS;
		return 0;
	}
	if (strcasecmp(s, "udp") == 0) {
		*out_type = EV_UDP_EGRESS;
		return 0;
	}

	return -EINVAL;
}

static int parse_ip_filter(const char *s, struct ip_filter *out)
{
	unsigned char buf[16];
	__u32 ip4;

	if (s == NULL || out == NULL)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	if (strcasecmp(s, "local") == 0 || strcasecmp(s, "localhost") == 0 ||
	    strcasecmp(s, "loopback") == 0) {
		out->set = true;
		out->loopback = true;
		return 0;
	}

	if (inet_pton(AF_INET, s, buf) == 1) {
		memcpy(&ip4, buf, sizeof(ip4));
		out->set = true;
		out->family = AF_INET;
		out->addr[0] = ntohl(ip4);
		return 0;
	}

	if (inet_pton(AF_INET6, s, buf) == 1) {
		out->set = true;
		out->family = AF_INET6;
		/* Keep IPv6 words in network byte order to match BPF comparisons. */
		memcpy(&out->addr[0], buf, sizeof(out->addr));
		return 0;
	}

	return -EINVAL;
}

/* Userspace only applies exe filtering; the rest is handled in BPF. */
static bool match_event_filter(const struct event_filter *f,
		       const char *exe_display)
{
	if (f == NULL)
		return true;

	if (f->has_exe) {
		if (exe_display == NULL || strcasestr(exe_display, f->exe) == NULL)
			return false;
	}

	return true;
}

static int add_exclude_port(struct event_filter *filter, const char *s)
{
	char *end = NULL;
	unsigned long port;

	if (filter == NULL || s == NULL)
		return -EINVAL;

	if (filter->exclude_port_count >= MAX_EXCLUDE_PORTS)
		return -ENOSPC;

	port = strtoul(s, &end, 10);
	if (end == s || *end != '\0' || port == 0 || port > 65535)
		return -EINVAL;

	filter->exclude_ports[filter->exclude_port_count++] = (__u16)port;
	return 0;
}

static int parse_pid(const char *s, __u32 *out_pid)
{
	char *end = NULL;
	unsigned long pid;

	if (s == NULL || out_pid == NULL)
		return -EINVAL;

	if (s[0] == '-')
		return -EINVAL;

	errno = 0;
	pid = strtoul(s, &end, 10);
	if (end == s || *end != '\0' || errno == ERANGE || pid == 0 || pid > UINT32_MAX)
		return -EINVAL;

	*out_pid = (__u32)pid;
	return 0;
}

static void format_ipv4(char *buf, size_t len, __u32 addr)
{
	struct in_addr in;
	in.s_addr = htonl(addr);
	inet_ntop(AF_INET, &in, buf, len);
}

static void format_ipv6(char *buf, size_t len, const __u32 *addr)
{
	struct in6_addr in6;
	memcpy(&in6.s6_addr32, addr, sizeof(in6.s6_addr32));
	inet_ntop(AF_INET6, &in6, buf, len);
}

enum { SUMMARY_EXE_MAX = 256 };

struct summary_key {
	__u32 pid;
	__u32 type;
	__u8 family;
	__u16 dport;
	__u32 saddr[4];
	__u32 daddr[4];
	char exe[SUMMARY_EXE_MAX];
};

struct summary_val {
	unsigned long long count;
	unsigned long long bytes;
};

struct summary_entry {
	bool in_use;
	struct summary_key key;
	struct summary_val val;
};

struct summary_table {
	struct summary_entry *entries;
	size_t cap;
	size_t len;
};

static unsigned long long fnv1a_hash(const void *data, size_t len)
{
	const unsigned char *bytes = data;
	unsigned long long hash = 1469598103934665603ULL;

	for (size_t i = 0; i < len; i++) {
		hash ^= (unsigned long long)bytes[i];
		hash *= 1099511628211ULL;
	}

	return hash;
}

static bool summary_key_equal(const struct summary_key *a, const struct summary_key *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static int summary_table_grow(struct summary_table *table, size_t new_cap)
{
	struct summary_entry *new_entries = calloc(new_cap, sizeof(*new_entries));
	if (new_entries == NULL)
		return -ENOMEM;

	for (size_t i = 0; i < table->cap; i++) {
		struct summary_entry *entry = &table->entries[i];
		if (!entry->in_use)
			continue;

		unsigned long long hash = fnv1a_hash(&entry->key, sizeof(entry->key));
		size_t idx = (size_t)(hash & (new_cap - 1));
		while (new_entries[idx].in_use) {
			idx = (idx + 1) & (new_cap - 1);
		}
		new_entries[idx] = *entry;
	}

	free(table->entries);
	table->entries = new_entries;
	table->cap = new_cap;
	return 0;
}

static int summary_table_init(struct summary_table *table)
{
	if (table == NULL)
		return -EINVAL;

	memset(table, 0, sizeof(*table));
	return summary_table_grow(table, 256);
}

static void summary_table_free(struct summary_table *table)
{
	if (table == NULL)
		return;

	free(table->entries);
	memset(table, 0, sizeof(*table));
}

static struct summary_entry *summary_table_get_or_add(struct summary_table *table,
						  const struct summary_key *key)
{
	if (table == NULL || key == NULL)
		return NULL;

	if (table->cap == 0 && summary_table_init(table) != 0)
		return NULL;

	if ((table->len + 1) * 100 >= table->cap * 70) {
		if (summary_table_grow(table, table->cap * 2) != 0)
			return NULL;
	}

	unsigned long long hash = fnv1a_hash(key, sizeof(*key));
	size_t idx = (size_t)(hash & (table->cap - 1));
	while (table->entries[idx].in_use) {
		if (summary_key_equal(&table->entries[idx].key, key))
			return &table->entries[idx];
		idx = (idx + 1) & (table->cap - 1);
	}

	table->entries[idx].in_use = true;
	table->entries[idx].key = *key;
	table->entries[idx].val.count = 0;
	table->entries[idx].val.bytes = 0;
	table->len++;
	return &table->entries[idx];
}

static int get_executable_path(pid_t pid, char *buf, size_t len)
{
	char path[64];
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%u/exe", pid);
	n = readlink(path, buf, len - 1);
	if (n < 0) {
		/* Process might have exited, fall back to comm */
		return -1;
	}
	buf[n] = '\0';
	return 0;
}


struct event_handler_ctx {
	struct ci_agent_broadcaster *broadcaster;
	struct bpf_map *dns_map;
	struct event_filter filter;
	struct summary_table *summary;
	bool summarize;
};

static int eventloop_register(int ep_fd, int fd, enum fd_tag tag)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.u32 = tag,
	};
	return epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct event_handler_ctx *handler_ctx = ctx;
	struct ci_agent_broadcaster *broadcaster = handler_ctx->broadcaster;
	struct bpf_map *dns_map = handler_ctx->dns_map;
	const struct event_filter *filter = &handler_ctx->filter;
	struct summary_table *summary = handler_ctx->summary;
	char saddr_str[INET6_ADDRSTRLEN];
	char daddr_str[INET6_ADDRSTRLEN];
	char exe_path[PATH_MAX];
	char hostname[MAX_HOSTNAME_LEN] = {0};
	const char *proto_str;
	const char *exe_display;
	const char *hostname_display = NULL;

	(void) data_sz;

	if (e->type == EV_TCP_EGRESS) {
		proto_str = "TCP";
	} else if (e->type == EV_UDP_EGRESS) {
		proto_str = "UDP";
	} else {
		return 0;
	}

	if (e->family != AF_INET && e->family != AF_INET6) {
		return 0;
	}

	/* Get full executable path */
	if (get_executable_path(e->pid, exe_path, sizeof(exe_path)) == 0) {
		exe_display = exe_path;
	} else {
		/* Fall back to comm if we can't read the path */
		exe_display = e->comm;
	}

	if (!match_event_filter(filter, exe_display))
		return 0;

	if (handler_ctx->summarize) {
		struct summary_key key;
		struct summary_entry *entry;

		memset(&key, 0, sizeof(key));
		key.pid = e->pid;
		key.type = e->type;
		key.family = e->family;
		key.dport = e->dport;
		memcpy(key.saddr, e->saddr, sizeof(key.saddr));
		memcpy(key.daddr, e->daddr, sizeof(key.daddr));
		snprintf(key.exe, sizeof(key.exe), "%.*s",
			 (int)(sizeof(key.exe) - 1),
			 exe_display);

		entry = summary_table_get_or_add(summary, &key);
		if (entry != NULL) {
			entry->val.count++;
			entry->val.bytes += (unsigned long long)e->bytes_sent;
		}

		return 0;
	}

	if (e->family == AF_INET) {
		format_ipv4(saddr_str, sizeof(saddr_str), e->saddr[0]);
		format_ipv4(daddr_str, sizeof(daddr_str), e->daddr[0]);
	} else {
		format_ipv6(saddr_str, sizeof(saddr_str), e->saddr);
		format_ipv6(daddr_str, sizeof(daddr_str), e->daddr);
	}

	/* Look up hostname from DNS map */
	if (dns_map) {
		struct dns_mapping_key key = {0};
		struct dns_mapping_value value = {0};
		
		if (e->family == AF_INET) {
			key.ip[0] = e->daddr[0];
			key.family = AF_INET;
		} else if (e->family == AF_INET6) {
			key.ip[0] = e->daddr[0];
			key.ip[1] = e->daddr[1];
			key.ip[2] = e->daddr[2];
			key.ip[3] = e->daddr[3];
			key.family = AF_INET6;
		}
		
		int map_fd = bpf_map__fd(dns_map);
		if (map_fd >= 0 && bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
			/* Found in DNS map - even if hostname is empty, this means DNS was captured */
			if (value.hostname[0] != '\0') {
				strncpy(hostname, value.hostname, sizeof(hostname) - 1);
				hostname[sizeof(hostname) - 1] = '\0';
				hostname_display = hostname;
			} else {
				/* DNS entry exists but hostname not extracted - show empty */
				hostname_display = "(empty)";
			}
		}
	}

	if (hostname_display) {
		ci_agent_broadcaster_send(broadcaster,
			"EGRESS ts=%llu pid=%u tgid=%u exe=%s proto=%s src=%s:%u dst=%s:%u (%s) bytes=%llu\n",
			(unsigned long long)e->ts_nsec,
			e->pid,
			e->tgid,
			exe_display,
			proto_str,
			saddr_str,
			e->sport,
			daddr_str,
			e->dport,
			hostname_display,
			(unsigned long long)e->bytes_sent);
	} else {
		ci_agent_broadcaster_send(broadcaster,
			"EGRESS ts=%llu pid=%u tgid=%u exe=%s proto=%s src=%s:%u dst=%s:%u bytes=%llu\n",
			(unsigned long long)e->ts_nsec,
			e->pid,
			e->tgid,
			exe_display,
			proto_str,
			saddr_str,
			e->sport,
			daddr_str,
			e->dport,
			(unsigned long long)e->bytes_sent);
	}

	return 0;
}

static int update_bpf_filter_config(struct ci_agent_bpf *skel,
				    const struct event_filter *filter)
{
	struct bpf_filter_config cfg = {0};
	__u32 key = 0;
	int map_fd;

	if (skel == NULL || filter == NULL)
		return -EINVAL;

	cfg.has_pid = filter->has_pid ? 1 : 0;
	cfg.pid = filter->pid;
	cfg.has_proto = filter->has_proto ? 1 : 0;
	cfg.type = filter->type;
	cfg.exclude_local_src = filter->exclude_local_src ? 1 : 0;
	cfg.exclude_local_dst = filter->exclude_local_dst ? 1 : 0;
	cfg.src.set = filter->src.set ? 1 : 0;
	cfg.src.loopback = filter->src.loopback ? 1 : 0;
	cfg.src.family = filter->src.family;
	memcpy(cfg.src.addr, filter->src.addr, sizeof(cfg.src.addr));
	cfg.dst.set = filter->dst.set ? 1 : 0;
	cfg.dst.loopback = filter->dst.loopback ? 1 : 0;
	cfg.dst.family = filter->dst.family;
	memcpy(cfg.dst.addr, filter->dst.addr, sizeof(cfg.dst.addr));
	if (filter->exclude_port_count > MAX_EXCLUDE_PORTS) {
		fprintf(stderr,
			"Warning: %zu exclude ports provided; only the first %d will be applied\n",
			filter->exclude_port_count,
			MAX_EXCLUDE_PORTS);
		cfg.exclude_port_count = MAX_EXCLUDE_PORTS;
	} else {
		cfg.exclude_port_count = (unsigned char)filter->exclude_port_count;
	}
	for (size_t i = 0; i < cfg.exclude_port_count; i++)
		cfg.exclude_ports[i] = filter->exclude_ports[i];

	map_fd = bpf_map__fd(skel->maps.filter_config_map);
	if (map_fd < 0)
		return -EINVAL;

	return bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
}

static int parse_duration_ms(const char *s, unsigned long long *out_ms)
{
	char *end = NULL;
	unsigned long long value;
	unsigned long long multiplier = 1000ULL;

	if (s == NULL || out_ms == NULL)
		return -EINVAL;

	errno = 0;
	value = strtoull(s, &end, 10);
	if (end == s || value == 0 || errno == ERANGE)
		return -EINVAL;

	if (*end == '\0') {
		multiplier = 1000ULL;
	} else if (strcmp(end, "ms") == 0) {
		multiplier = 1ULL;
	} else if (strcmp(end, "s") == 0) {
		multiplier = 1000ULL;
	} else if (strcmp(end, "m") == 0) {
		multiplier = 60ULL * 1000ULL;
	} else if (strcmp(end, "h") == 0) {
		multiplier = 60ULL * 60ULL * 1000ULL;
	} else {
		return -EINVAL;
	}

	if (value > ULLONG_MAX / multiplier)
		return -EINVAL;
	*out_ms = value * multiplier;
	if (*out_ms == 0)
		return -EINVAL;

	return 0;
}

static int parse_sort_by(const char *s, enum summary_sort_by *out)
{
	if (s == NULL || out == NULL)
		return -EINVAL;

	if (strcasecmp(s, "count") == 0) {
		*out = SUMMARY_SORT_COUNT;
		return 0;
	}
	if (strcasecmp(s, "bytes") == 0) {
		*out = SUMMARY_SORT_BYTES;
		return 0;
	}

	return -EINVAL;
}

static unsigned long long get_mono_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000ULL +
	       (unsigned long long)ts.tv_nsec / 1000000ULL;
}

static void emit_summary_line(struct ci_agent_broadcaster *broadcaster, const char *fmt, ...)
{
	char buf[8192];
	va_list va;
	int len;

	va_start(va, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	if (len < 0)
		return;

	if (broadcaster != NULL)
		ci_agent_broadcaster_send(broadcaster, "%s", buf);

	fputs(buf, stdout);
}

static int summary_cmp_count(const void *a, const void *b)
{
	const struct summary_entry *ea = *(const struct summary_entry * const *)a;
	const struct summary_entry *eb = *(const struct summary_entry * const *)b;

	if (ea->val.count < eb->val.count)
		return 1;
	if (ea->val.count > eb->val.count)
		return -1;
	return 0;
}

static int summary_cmp_bytes(const void *a, const void *b)
{
	const struct summary_entry *ea = *(const struct summary_entry * const *)a;
	const struct summary_entry *eb = *(const struct summary_entry * const *)b;

	if (ea->val.bytes < eb->val.bytes)
		return 1;
	if (ea->val.bytes > eb->val.bytes)
		return -1;
	return 0;
}

static void emit_summary(struct summary_table *table,
				 struct ci_agent_broadcaster *broadcaster,
				 enum summary_sort_by sort_by,
				 const char *duration_label)
{
	if (table == NULL)
		return;

	struct summary_entry **items = NULL;
	if (table->len > 0) {
		items = calloc(table->len, sizeof(*items));
		if (items == NULL)
			return;
	}

	size_t idx = 0;
	for (size_t i = 0; i < table->cap; i++) {
		if (!table->entries[i].in_use)
			continue;
		items[idx++] = &table->entries[i];
	}

	if (idx > 1) {
		if (sort_by == SUMMARY_SORT_BYTES)
			qsort(items, idx, sizeof(*items), summary_cmp_bytes);
		else
			qsort(items, idx, sizeof(*items), summary_cmp_count);
	}

	emit_summary_line(broadcaster, "SUMMARY interval=%s entries=%zu sort-by=%s\n",
			duration_label ? duration_label : "unknown",
			idx,
			sort_by == SUMMARY_SORT_BYTES ? "bytes" : "count");

	for (size_t i = 0; i < idx; i++) {
		const struct summary_entry *entry = items[i];
		char saddr_str[INET6_ADDRSTRLEN];
		char daddr_str[INET6_ADDRSTRLEN];
		const char *proto_str = entry->key.type == EV_TCP_EGRESS ? "TCP" : "UDP";

		if (entry->key.family == AF_INET) {
			format_ipv4(saddr_str, sizeof(saddr_str), entry->key.saddr[0]);
			format_ipv4(daddr_str, sizeof(daddr_str), entry->key.daddr[0]);
		} else {
			format_ipv6(saddr_str, sizeof(saddr_str), entry->key.saddr);
			format_ipv6(daddr_str, sizeof(daddr_str), entry->key.daddr);
		}

		emit_summary_line(broadcaster,
			"pid=%u proto=%s exe=%s src=%s dst=%s dport=%u count=%llu bytes=%llu\n",
			entry->key.pid,
			proto_str,
			entry->key.exe,
			saddr_str,
			daddr_str,
			entry->key.dport,
			entry->val.count,
			entry->val.bytes);
	}

	free(items);
}

int main(int argc, char **argv)
{
	struct event_filter filter = {0};
	struct summary_table summary_table = {0};
	int opt;
	int opt_index = 0;
	bool summarize = false;
	unsigned long long summarize_ms = 0;
	const char *summarize_label = NULL;
	enum summary_sort_by sort_by = SUMMARY_SORT_COUNT;

	static struct option long_opts[] = {
		{"pid", required_argument, NULL, 'p'},
		{"proto", required_argument, NULL, 'P'},
		{"exe", required_argument, NULL, 'e'},
		{"src", required_argument, NULL, 's'},
		{"dst", required_argument, NULL, 'd'},
		{"no-port", required_argument, NULL, 'x'},
		{"summarize", required_argument, NULL, 'S'},
		{"sort-by", required_argument, NULL, 'o'},
		{"no-local-src", no_argument, NULL, 1},
		{"no-local-dst", no_argument, NULL, 2},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};

	while ((opt = getopt_long(argc, argv, "p:P:e:s:d:x:S:o:h", long_opts, &opt_index)) != -1) {
		switch (opt) {
			case 'p':
				if (parse_pid(optarg, &filter.pid) != 0) {
					fprintf(stderr, "invalid pid: %s\n", optarg);
					print_usage(argv[0]);
					return 1;
				}
				filter.has_pid = true;
				break;
			case 'P':
				if (parse_proto(optarg, &filter.type) != 0) {
					fprintf(stderr, "invalid proto: %s\n", optarg);
					print_usage(argv[0]);
					return 1;
				}
				filter.has_proto = true;
				break;
			case 'e':
				filter.has_exe = true;
				{
					size_t n = strnlen(optarg, sizeof(filter.exe));
					if (n >= sizeof(filter.exe)) {
						fprintf(stderr, "exe substring too long (max %zu bytes)\n", sizeof(filter.exe) - 1);
						print_usage(argv[0]);
						return 1;
					}
					memcpy(filter.exe, optarg, n);
					filter.exe[n] = '\0';
				}
				break;
			case 's':
				if (parse_ip_filter(optarg, &filter.src) != 0) {
					fprintf(stderr, "invalid source IP: %s\n", optarg);
					print_usage(argv[0]);
					return 1;
				}
				break;
			case 'd':
				if (parse_ip_filter(optarg, &filter.dst) != 0) {
					fprintf(stderr, "invalid destination IP: %s\n", optarg);
					print_usage(argv[0]);
					return 1;
				}
				break;
			case 'x':
				{
					int r = add_exclude_port(&filter, optarg);
					if (r != 0) {
						if (r == -ENOSPC)
							fprintf(stderr, "too many --no-port options (max %d)\n", MAX_EXCLUDE_PORTS);
						else
							fprintf(stderr, "invalid port: %s\n", optarg);
						print_usage(argv[0]);
						return 1;
					}
				}
				break;
			case 'S':
				if (parse_duration_ms(optarg, &summarize_ms) != 0) {
					fprintf(stderr, "invalid summarize duration: %s\n", optarg);
					print_usage(argv[0]);
					return 1;
				}
				summarize = true;
				summarize_label = optarg;
				break;
			case 'o':
				if (parse_sort_by(optarg, &sort_by) != 0) {
					fprintf(stderr, "invalid sort key: %s\n", optarg);
					print_usage(argv[0]);
					return 1;
				}
				break;
			case 1:
				filter.exclude_local_src = true;
				break;
			case 2:
				filter.exclude_local_dst = true;
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			default:
				print_usage(argv[0]);
				return 1;
		}
	}

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	int exit_code = 1;
	int err;
	bool dns_started = false;
	int ep_fd = -1;
	struct ring_buffer *rb = NULL;
	struct ci_agent_broadcaster *broadcaster = NULL;
	struct ci_agent_bpf *skel = NULL;

	err = ci_agent_broadcaster_init(&broadcaster, "/run/ci-agent.sock");
	if (err != 0) {
		fprintf(stderr, "initializing listener failed: %s\n", strerror(-err));
		goto out;
	}

	skel = ci_agent_bpf__open();
	if (!skel) {
		fprintf(stderr, "open skeleton failed: %s\n", strerror(errno));
		goto out;
	}
	err = ci_agent_bpf__load(skel);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		goto out;
	}

	err = update_bpf_filter_config(skel, &filter);
	if (err) {
		fprintf(stderr, "setting BPF filter failed: %s\n", strerror(-err));
		goto out;
	}
	err = ci_agent_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(-err));
		fprintf(stderr, "Note: If a previous instance was killed, you may need to:\n");
		fprintf(stderr, "  1. Wait a few seconds for kernel to clean up\n");
		fprintf(stderr, "  2. Or reboot to clear stuck BPF attachments\n");
		goto out;
	}

	fprintf(stderr, "ci-agentd started successfully\n");

	/* Start DNS sniffer thread */
	int dns_map_fd = bpf_map__fd(skel->maps.dns_map);
	if (dns_map_fd >= 0) {
		if (dns_sniffer_start(dns_map_fd) == 0) {
			dns_started = true;
			fprintf(stderr, "DNS sniffer started\n");
		} else {
			fprintf(stderr, "Warning: DNS sniffer failed to start (need CAP_NET_RAW)\n");
		}
	}

	struct event_handler_ctx handler_ctx = {
		.broadcaster = broadcaster,
		.dns_map = skel->maps.dns_map,
		.filter = filter,
		.summary = &summary_table,
		.summarize = summarize,
	};

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			 handle_event, &handler_ctx, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		goto out;
	}

	int rb_fd = ring_buffer__epoll_fd(rb);
	if (rb_fd < 0)
	{
		fprintf(stderr, "ring_buffer__epoll_fd: %s\n", strerror(errno));
		goto out;
	}

	ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0)
	{
		fprintf(stderr, "epoll_create1: %s\n", strerror(errno));
		goto out;
	}

	if (eventloop_register(ep_fd, rb_fd, FD_RINGBUF) < 0)
	{
		fprintf(stderr, "epoll_ctl ringbuf: %s\n", strerror(errno));
		goto out;
	}

	int lfd = ci_agent_broadcaster_fd(broadcaster);
	if (eventloop_register(ep_fd, lfd, FD_LISTENER) < 0)
	{
		fprintf(stderr, "epoll_ctl listener: %s\n", strerror(errno));
		goto out;
	}

	unsigned long long deadline_ms = 0;
	if (summarize)
		deadline_ms = get_mono_ms() + summarize_ms;

	while (!stop) {
		struct epoll_event events[8];
		int timeout_ms = -1;

		if (summarize) {
			unsigned long long now = get_mono_ms();
			if (now >= deadline_ms)
				break;
			unsigned long long remaining = deadline_ms - now;
			if (remaining > (unsigned long long)INT_MAX)
				timeout_ms = INT_MAX;
			else
				timeout_ms = (int)remaining;
		}

		int n = epoll_wait(ep_fd, events, 8, timeout_ms);
		if (n < 0)
		{
			if (errno == EINTR) {
				/* Check stop flag after signal interruption */
				if (stop)
					break;
				continue;
			}

			fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
			break;
		}

		for (int i = 0; i < n; i++)
		{
			switch (events[i].data.u32)
			{
				case FD_RINGBUF:
				{
					int r = ring_buffer__poll(rb, 0);
					if (r < 0)
						fprintf(stderr, "process ringbuf: %s\n", strerror(errno));
					break;
				}

				case FD_LISTENER:
				{
					int r = ci_agent_broadcaster_accept(broadcaster);
					if (r < 0)
						fprintf(stderr, "accept: %s\n", strerror(r));
					break;
				}

				default:
					break;
			}
		}
	}

	if (summarize)
		emit_summary(&summary_table, broadcaster, sort_by, summarize_label);

	fprintf(stderr, "ci-agentd shutting down...\n");

	exit_code = 0;

out:
	summary_table_free(&summary_table);
	if (dns_started)
		dns_sniffer_stop_thread();
	if (ep_fd >= 0)
		close(ep_fd);
	if (rb)
		ring_buffer__free(rb);
	if (skel)
		ci_agent_bpf__destroy(skel);
	if (broadcaster)
		ci_agent_broadcaster_fini(broadcaster);

	return exit_code;
}
