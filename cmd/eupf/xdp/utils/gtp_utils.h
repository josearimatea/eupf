/**
 * Copyright 2023 Edgecom LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>

#include "xdp/utils/gtpu.h"
#include "xdp/utils/packet_context.h"

static __always_inline __u32 parse_gtp(struct packet_context *ctx) {
    struct gtpuhdr *gtp = (struct gtpuhdr *)ctx->data;
    if ((void *)(gtp + 1) > ctx->data_end)
        return -1;

    ctx->data += sizeof(*gtp);
    ctx->gtp = gtp;
    return gtp->message_type;
}

static __always_inline __u32 handle_echo_request(struct packet_context *ctx) {
    struct ethhdr *eth = ctx->eth;
    struct iphdr *iph = ctx->ip4;
    struct udphdr *udp = ctx->udp;
    struct gtpuhdr *gtp = ctx->gtp;

    gtp->message_type = GTPU_ECHO_RESPONSE;

    /* TODO: add support GTP over IPv6 */
    swap_ip(iph);
    swap_port(udp);
    swap_mac(eth);
    bpf_printk("upf: send gtp echo response [ %pI4 -> %pI4 ]", &iph->saddr, &iph->daddr);
    return XDP_TX;
}



static __always_inline long remove_gtp_header(struct packet_context *ctx) {
    if (!ctx->gtp) {
        bpf_printk("upf: remove_gtp_header: not a gtp packet");
        return -1;
    }

    size_t ext_gtp_header_size = 0;
    struct gtpuhdr *gtp = ctx->gtp;
    if (gtp->e || gtp->s || gtp->pn)
        ext_gtp_header_size += sizeof(struct gtp_hdr_ext) + 4;

    const size_t GTP_ENCAPSULATED_SIZE = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtpuhdr) + ext_gtp_header_size;

    void *data = (void *)(long)ctx->xdp_ctx->data;
    void *data_end = (void *)(long)ctx->xdp_ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("upf: remove_gtp_header: can't parse eth");
        return -1;
    }

    struct ethhdr *new_eth = data + GTP_ENCAPSULATED_SIZE;
    if ((void *)(new_eth + 1) > data_end) {
        bpf_printk("upf: remove_gtp_header: can't set new eth");
        return -1;
    }
    __builtin_memcpy(new_eth, eth, sizeof(*eth));

    long result = bpf_xdp_adjust_head(ctx->xdp_ctx, GTP_ENCAPSULATED_SIZE);
    if (result)
        return result;

    /* Update packet pointers */
    return context_reinit(ctx, (void *)(long)ctx->xdp_ctx->data, (void *)(long)ctx->xdp_ctx->data_end);
}

static __always_inline void fill_ip_header(struct iphdr *ip, int saddr, int daddr, int tot_len) {
    ip->version = 4;
    ip->ihl = 5;  /* No options */
    ip->tos = 0;
    ip->tot_len = bpf_htons(tot_len);
    ip->id = 0;             /* No fragmentation */
    ip->frag_off = 0x0040;  /* Don't fragment; Fragment offset = 0 */
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = saddr;
    ip->daddr = daddr;
}

static __always_inline void fill_udp_header(struct udphdr *udp, int port, int len) {
    udp->source = bpf_htons(port);
    udp->dest = udp->source;
    udp->len = bpf_htons(len);
    udp->check = 0;
}

static __always_inline void fill_gtp_header(struct gtpuhdr *gtp, int teid, int len) {
    *(__u8*)gtp = GTP_FLAGS;
    gtp->message_type = GTPU_G_PDU;
    gtp->message_length = bpf_htons(len);
    gtp->teid = bpf_htonl(teid);
}

static __always_inline __u32 add_gtp_over_ip4_headers(struct packet_context *ctx, int saddr, int daddr, int teid) {
    static const size_t GTP_ENCAPSULATED_SIZE = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct gtpuhdr);

    //int ip_packet_len = (ctx->xdp_ctx->data_end - ctx->xdp_ctx->data) - sizeof(*eth);
    int ip_packet_len = 0;
    if(ctx->ip4)
        ip_packet_len = bpf_ntohs(ctx->ip4->tot_len);
    else if(ctx->ip6)
        ip_packet_len = bpf_ntohs(ctx->ip6->payload_len) + sizeof(struct ipv6hdr);
    else
        return -1;

    int result = bpf_xdp_adjust_head(ctx->xdp_ctx, (__s32)-GTP_ENCAPSULATED_SIZE);
    if(result)
        return -1;

    void *data = (void *)(long)ctx->xdp_ctx->data;
    void *data_end = (void *)(long)ctx->xdp_ctx->data_end;

    struct ethhdr *orig_eth = data + GTP_ENCAPSULATED_SIZE;
    if ((void *)(orig_eth + 1) > data_end)
        return -1;

    struct ethhdr *eth = data;
    __builtin_memcpy(eth, orig_eth, sizeof(*eth));
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    /* Add the outer IP header */
    fill_ip_header(ip, saddr, daddr, ip_packet_len + GTP_ENCAPSULATED_SIZE);

    /* Add the UDP header */
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return -1;

    fill_udp_header(udp, GTP_UDP_PORT, ip_packet_len + sizeof(*udp) + sizeof(struct gtpuhdr));

    /* Add the GTP header */
    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return -1;

    fill_gtp_header(gtp, teid, ip_packet_len);

    ip->check = ipv4_csum(ip, sizeof(*ip));

    /* TODO: implement UDP csum which pass ebpf verifier checks successfully */
    // cs = 0;
    // const void* udp_start = (void*)udp;
    // const __u16 udp_len = bpf_htons(udp->len);
    // ipv4_l4_csum(udp, udp_len, &cs, ip);
    // udp->check = cs;

    /* Update packet pointers */
    context_reset_ip4(ctx, (void *)(long)ctx->xdp_ctx->data, (void *)(long)ctx->xdp_ctx->data_end, eth, ip, udp, gtp);
    return 0;
}