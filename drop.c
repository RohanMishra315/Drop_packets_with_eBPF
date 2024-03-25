
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <iproute2/bpf_elf.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);

} port_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);

} pkt_count SEC(".maps");

SEC("xdp")
int drop_packets(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);

    if ((void *)tcp + sizeof(*tcp) > data_end)
        return XDP_PASS;

    // Check if it's a TCP packet
    if (ip->protocol == IPPROTO_TCP)
    {
        __u32 key0 = 0;
        __u32 *port = bpf_map_lookup_elem(&port_map, &key0);
        __u32 *count = bpf_map_lookup_elem(&pkt_count, &key0);

        // if port is not passed from userspace Golang program.

        if (port != NULL)
        {
            if (*port < 0)
            {
                *port = 4040; // default
            }

            if (bpf_ntohs(tcp->dest) == *port) 
            {
                if (count)
                {
                    __sync_fetch_and_add(count, 1);
                }

                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";