#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

#define MAX_ENTRIES 10000

struct packet_feature {
    __u64 timestamp_ns;      // nanosecond timestamp
    __u32 packet_size;       // total packet size
    __u32 src_ip;            // source IP
    __u32 dst_ip;            // destination IP
    __u16 src_port;          // source port
    __u16 dst_port;          // destination port
    __u8 protocol;           // IPPROTO_TCP, IPPROTO_UDP, etc.
    __u8 tcp_flags;          // TCP flags (SYN, ACK, FIN, etc.)
    __u16 payload_size;      // payload size (packet_size - headers)
};

// Ring buffer for sending packet features to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} packet_features SEC(".maps");

// Atomic counter for packets processed
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_count SEC(".maps");

// XDP program - processes at driver level for maximum performance
SEC("xdp")
int xdp_packet_feature(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Initialize packet feature structure
    struct packet_feature *pf = bpf_ringbuf_reserve(&packet_features, sizeof(*pf), 0);
    if (!pf)
        return XDP_PASS;

    // Capture basic packet info
    pf->timestamp_ns = bpf_ktime_get_ns();
    pf->packet_size = ctx->data_end - ctx->data;
    pf->src_ip = ip->saddr;
    pf->dst_ip = ip->daddr;
    pf->protocol = ip->protocol;
    pf->tcp_flags = 0;
    pf->src_port = 0;
    pf->dst_port = 0;
    pf->payload_size = 0;

    // Parse TCP/UDP headers
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(pf, 0);
            return XDP_PASS;
        }
        pf->src_port = bpf_ntohs(tcp->source);
        pf->dst_port = bpf_ntohs(tcp->dest);
        pf->tcp_flags = tcp->flags;
        pf->payload_size = pf->packet_size - ((ip->ihl * 4) + (tcp->doff * 4));
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            bpf_ringbuf_discard(pf, 0);
            return XDP_PASS;
        }
        pf->src_port = bpf_ntohs(udp->source);
        pf->dst_port = bpf_ntohs(udp->dest);
        pf->payload_size = pf->packet_size - ((ip->ihl * 4) + sizeof(struct udphdr));
    }

    // Submit the feature to ring buffer
    bpf_ringbuf_submit(pf, 0);

    // Update packet count
    __u32 idx = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &idx);
    if (count)
        __sync_fetch_and_add(count, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
