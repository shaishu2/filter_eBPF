#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr_t {
    __be16 tci;
    __be16 encap_proto;
};

struct gre_hdr_t {
    __be16 flags;
    __be16 proto;
};

struct erspan_hdr_t {
    __u16 ver_vlan;    
    __u16 cos_sessid;  
    __u32 index;       
};

SEC("xdp_prog")
int xdp_cip_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    void *ptr      = data;
    if (ptr + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    struct ethhdr *eth = ptr;
    ptr += sizeof(*eth);

    __u16 eth_proto = eth->h_proto;
    if (eth_proto == __constant_htons(ETH_P_8021Q)) {
        if (ptr + sizeof(struct vlan_hdr_t) > data_end)
            return XDP_PASS;
        struct vlan_hdr_t *vh = ptr;
        eth_proto = vh->encap_proto;
        ptr += sizeof(*vh);
    }

    if (eth_proto != __constant_htons(ETH_P_IP) ||
        ptr + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    struct iphdr *iph = ptr;
    if (iph->protocol != IPPROTO_GRE)
        return XDP_PASS;
    ptr += iph->ihl * 4;

    if (ptr + sizeof(struct gre_hdr_t) > data_end)
        return XDP_PASS;
    struct gre_hdr_t *gre = ptr;
    if (gre->proto != __constant_htons(0x88BE)) 
        return XDP_PASS;
    ptr += sizeof(*gre);
    if (gre->flags & __constant_htons(0x1000)) {
        if (ptr + 4 > data_end)
            return XDP_PASS;
        ptr += 4;
    }

    if (ptr + sizeof(struct erspan_hdr_t) > data_end)
        return XDP_PASS;
    ptr += sizeof(struct erspan_hdr_t);

    if (ptr + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    eth = ptr;
    ptr += sizeof(*eth);
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    if (ptr + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    iph = ptr;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
    ptr += iph->ihl * 4;

    if (ptr + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    struct tcphdr *tcph = ptr;
    ptr += tcph->doff * 4;

    __u16 cip_be = __constant_htons(44818);
    if (tcph->dest != cip_be && tcph->source != cip_be)
        return XDP_PASS;

    __u16 total_len   = __constant_htons(iph->tot_len);
    __u16 ip_hdr_len  = iph->ihl * 4;
    __u16 tcp_hdr_len = tcph->doff * 4;
    __u16 payload_len = total_len - ip_hdr_len - tcp_hdr_len;
    if (ptr + payload_len > data_end)
        return XDP_PASS;

    if (payload_len >= 47) {
        if ((void *)(ptr + 47) > data_end)
            return XDP_PASS;
        __u8 svc = *(__u8 *)(ptr + 46);
        if (svc == 16 || svc == 144)
            return XDP_DROP;
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
