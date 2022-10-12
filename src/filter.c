
#define KBUILD_MODNAME "filter"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/bpf_verifier.h>

#define N_SESSIONS 100000
#define INGRESS_MAGIC 0xfaceb00c
#define EGRESS_MAGIC 0xfaceb00d
#define SMOOTHED_RTT_FRAC 7/8
#define RTTVAR_FRAC 3/4

BPF_PERF_OUTPUT(skb_events);
BPF_HASH(spin_bits, u64, u8);
BPF_HASH(smoothed_rtts, u64, u64);
BPF_HASH(smoothed_rttvars, u64, u64);
BPF_HASH(last_rtt_times, u64, u64);

// This header is a reduced version of the quic_hdr struct,
// and is used only for determining whether the packet is a QUIC packet.

struct quichdr_init {
    __u8 flags;
};

struct quichdr_long {
    __u8 flags;
    // Header Form (1) = 1,
    // Fixed Bit (1) = 1,
    // Long Packet Type (2),
    // Type-Specific Bits (4),
    __u32 version;
    __u8 dest_connection_id_length;
    __u8 dest_connection_id[20];
    __u8 source_connection_id_length;
    __u8 source_connection_id[20];
    // ...
    // Type-Specific Payload (..),
}__attribute__((packed));

struct quichdr_short { // 1-RTT
    __u8 flags;
    // Header Form (1) = 0,
    // Fixed Bit (1) = 1,
    // Spin Bit (1),
    // Reserved Bits (2),
    // Key Phase (1),
    // Packet Number Length (2),
    __u8 dest_connection_id[20];
    __u32 packet_number;
    // ...
    // Packet Payload (8..),
}__attribute__((packed));

typedef enum mode {
    MODE_XDP,
    MODE_TC
} mode;

    
static int udpfilter(void* data, void* data_end, __u8 pass_code) {
    // Debug: print last byte
    //bpf_trace_printk("BT:  %d\n", *(__u8*)(data_end - 1));
    //bpf_trace_printk("LEN: %d\n", (void*)data_end - (void*)data);

    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end) {
        return pass_code;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)){
        return pass_code;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return pass_code;
    }

    if (((int)ip->version) != 4) {// && ((int)ip->version) != 6) {
        return pass_code;
    }
    if (ip->protocol != IPPROTO_UDP) {
        return pass_code;
    }

    // Now we check if the UDP packet is actually a QUIC packet
    // For the purposes of this program, we 
    __u8 ip_header_len = ip->ihl << 2;

    struct udphdr *udp = data + sizeof(*eth) + ip_header_len;
    if ((void *) udp + sizeof(*udp) > data_end) {
        return pass_code;
    }

    __u32 udp_header_len = sizeof(*udp);

    struct quichdr_init *quic = data + sizeof(*eth) + ip_header_len + udp_header_len;
    if ((void *) quic + sizeof(*quic) > data_end) {
        return pass_code;
    }

    // The second bit is fixed and is always 1
    if (! ((quic->flags & 0b01000000) >> 6)) {
        return pass_code;
    }
    
    // If the first bit of the flags is 1, then is a long header, else it is short
    if ((quic->flags & 0b10000000) >> 7) {
        struct quichdr_long *quic_long = data + sizeof(*eth) + ip_header_len + udp_header_len;
        if ((void *) quic_long + sizeof(*quic_long) > data_end) {
            return pass_code;
        }
/*
        spin_bits.lookup_or_try_init(&quic_long->dest_connection_id, 0);
        smoothed_rtts.lookup_or_try_init(&quic_long->dest_connection_id, 0);
        smoothed_rttvars.lookup_or_try_init(&quic_long->dest_connection_id, 0);
        last_rtt_times.lookup_or_try_init(&quic_long->dest_connection_id, 0);
*/
    } else {
        struct quichdr_short *quic_short = data + sizeof(*eth) + ip_header_len + udp_header_len;
        if ((void *) quic_short + sizeof(*quic_short) > data_end) {
            return pass_code;
        }
/*

        // Short header -> we can calculate RTT
        __u64 packet_time = bpf_ktime_get_ns();
        __u8 current_spin = (quic_short->flags & 0b00100000) >> 5;

        __u8 packet_number_length = (quic_short->flags & 0b00000011) + 1;
 
        bpf_trace_printk("dest_connection_id: %x\n", quic_short->dest_connection_id);
        __u8 last_spin_bit = spin_bits.lookup_or_try_init(&quic_short->dest_connection_id, &current_spin);

        if (last_spin_bit != current_spin) {
            spin_bits.update(&quic_short->dest_connection_id, &current_spin);

            __u64 smoothed_rtt = smoothed_rtts.lookup(&quic_short->dest_connection_id);
            __u64 rttvar = smoothed_rttvars.lookup(&quic_short->dest_connection_id);
            __u64 latest_rtt = last_rtt_times.lookup(&quic_short->dest_connection_id);

            if (smoothed_rtt == NULL || rttvar == NULL || latest_rtt == NULL) {
                return pass_code;
            }

            smoothed_rtt = SMOOTHED_RTT_FRAC * smoothed_rtt + (1 - SMOOTHED_RTT_FRAC) * latest_rtt;

            __u64 rttvar_sample;
            if (smoothed_rtt > latest_rtt) {
                rttvar_sample = smoothed_rtt - latest_rtt;
            } else {
                rttvar_sample = latest_rtt - smoothed_rtt;
            }

            rttvar = RTTVAR_FRAC * rttvar + (1 - RTTVAR_FRAC) * rttvar_sample;

            smoothed_rtts.update(&quic_short->dest_connection_id, &smoothed_rtt);
            smoothed_rttvars.update(&quic_short->dest_connection_id, &rttvar);
            last_rtt_times.update(&quic_short->dest_connection_id, &packet_time);
            bpf_trace_printk("RTT: %llu\n", smoothed_rtt);
        }*/
    }
    // Verify sanity of the version. In this experiment,
    // we only support traffic on version 0x00000001
    // if (quic_long->version != 0x00000001) {
    //     return TC_ACT_OK;
    // }
    
    // Now we can pass the packet to the user space
    return -1;
}

int ingress_filter_tc(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int res = udpfilter(data, data_end, TC_ACT_OK);

    if (res == -1) {
        int ingress_magic = INGRESS_MAGIC;
        skb_events.perf_submit_skb(ctx, ctx->len, &ingress_magic, sizeof(ingress_magic));
        res = TC_ACT_OK;
    }

    return res;
}

int ingress_filter_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int res = udpfilter(data, data_end, XDP_PASS);

    if (res == -1) {
        int ingress_magic = INGRESS_MAGIC;
        skb_events.perf_submit_skb(ctx, ctx->data_end - ctx->data, &ingress_magic, sizeof(ingress_magic));
        res = XDP_PASS;
    }

    return res;
}

int egress_filter(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int res = udpfilter(data, data_end, TC_ACT_OK);

    if (res == -1) {
        int egress_magic = EGRESS_MAGIC;
        skb_events.perf_submit_skb(ctx, ctx->len, &egress_magic, sizeof(egress_magic));
        res = TC_ACT_OK;
    }

    return res;
}