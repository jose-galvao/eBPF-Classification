#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

struct gtpu_header {
    u8 flags;
    u8 message_type;
    u16 length;
    u32 teid;
};

#define GTPU_PORT 2152
#define GTPU_CONTROL_PORT 2123

struct transport_header_simple {
    u16 source;
    u16 dest;
};

struct flow_key_ts {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

struct ip_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    s64 inter_arrival_time_ns;
    u32 tam_packet;
    u8 protocol;
    u32 teid;
    s32 classificacao; //envia -1 (S/C)
};

// mapas
BPF_PERF_OUTPUT(events);
BPF_HASH(flow_stats, struct flow_key_ts, u64, 10240);

int monitor_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end) return XDP_PASS;
    if (outer_ip->protocol != IPPROTO_UDP) return XDP_PASS;

    u32 outer_ip_len = outer_ip->ihl * 4;
    struct udphdr *udp = (void *)outer_ip + outer_ip_len;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    if (udp->dest != htons(GTPU_PORT) && udp->dest != htons(GTPU_CONTROL_PORT))
        return XDP_PASS;

    struct gtpu_header *gtpu = (void *)(udp + 1);
    if ((void *)(gtpu + 1) > data_end) return XDP_PASS;

    struct iphdr *inner_ip = NULL;
    u32 offsets[] = {8, 12, 16, 20, 4};

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        void *test_ptr = (void *)gtpu + offsets[i];
        if (test_ptr + sizeof(struct iphdr) > data_end) continue;
        struct iphdr *t_ip = (struct iphdr *)test_ptr;
        if (t_ip->version == 4 && t_ip->ihl >= 5) {
            inner_ip = t_ip;
            break;
        }
    }
    if (!inner_ip) return XDP_PASS;

    u32 inner_ip_len = inner_ip->ihl * 4;
    if ((void *)inner_ip + inner_ip_len > data_end) return XDP_PASS;

    // extrai dados
    u64 current_ktime_ns = bpf_ktime_get_ns();
    u32 inner_packet_size = ntohs(inner_ip->tot_len);

    struct flow_key_ts flow_key = {};
    flow_key.src_ip = inner_ip->saddr;
    flow_key.dst_ip = inner_ip->daddr;
    flow_key.protocol = inner_ip->protocol;
    flow_key.src_port = 0;
    flow_key.dst_port = 0;

    struct ip_event evt = {};
    evt.src_ip = inner_ip->saddr;
    evt.dst_ip = inner_ip->daddr;
    evt.tam_packet = inner_packet_size;
    evt.protocol = inner_ip->protocol;
    evt.teid = ntohl(gtpu->teid);
    evt.classificacao = -1; // decidido no python
    evt.inter_arrival_time_ns = 0;

    if (inner_ip->protocol == IPPROTO_TCP || inner_ip->protocol == IPPROTO_UDP) {
        void *trans = (void *)inner_ip + inner_ip_len;
        if (trans + sizeof(struct transport_header_simple) <= data_end) {
            struct transport_header_simple *th = (struct transport_header_simple *)trans;
            evt.src_port = bpf_ntohs(th->source);
            evt.dst_port = bpf_ntohs(th->dest);
            flow_key.src_port = evt.src_port;
            flow_key.dst_port = evt.dst_port;
        }
    }


    u64 *prev_ts = flow_stats.lookup(&flow_key);
    if (prev_ts) {
        s64 delta = (s64)(current_ktime_ns - *prev_ts);
        if (delta > 0) evt.inter_arrival_time_ns = delta;
    }
    flow_stats.update(&flow_key, &current_ktime_ns);

    // envia para o python
    events.perf_submit(ctx, &evt, sizeof(evt));

    return XDP_PASS;
}