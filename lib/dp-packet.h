/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DPBUF_H
#define DPBUF_H 1

#include <stddef.h>
#include <stdint.h>

#ifdef DPDK_NETDEV
#include <rte_config.h>
#include <rte_mbuf.h>
#endif

#include "csum.h"
#include "netdev-afxdp.h"
#include "netdev-dpdk.h"
#include "openvswitch/list.h"
#include "packets.h"
#include "util.h"
#include "flow.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum OVS_PACKED_ENUM dp_packet_source {
    DPBUF_MALLOC,              /* Obtained via malloc(). */
    DPBUF_STACK,               /* Un-movable stack space or static buffer. */
    DPBUF_STUB,                /* Starts on stack, may expand into heap. */
    DPBUF_DPDK,                /* buffer data is from DPDK allocated memory.
                                * ref to dp_packet_init_dpdk() in dp-packet.c.
                                */
    DPBUF_AFXDP,               /* Buffer data from XDP frame. */
};

#define DP_PACKET_CONTEXT_SIZE 64

/* Bit masks for the 'offloads' member of the 'dp_packet' structure. */
enum OVS_PACKED_ENUM dp_packet_offload_mask {
    /* Bad IP checksum in the packet. */
    DP_PACKET_OL_IP_CKSUM_BAD = UINT16_C(1) << 4,
    /* Valid IP checksum in the packet. */
    DP_PACKET_OL_IP_CKSUM_GOOD = UINT16_C(1) << 7,

    /* Bad L4 checksum in the packet. */
    DP_PACKET_OL_L4_CKSUM_BAD = UINT16_C(1) << 3,
    /* Valid L4 checksum in the packet. */
    DP_PACKET_OL_L4_CKSUM_GOOD = UINT16_C(1) << 8,

    /* Protocol corresponding to above L4 checksums. */
    DP_PACKET_OL_L4_PROTO_TCP = UINT16_C(1) << 9,
    DP_PACKET_OL_L4_PROTO_UDP = UINT16_C(1) << 10,

    /* Bits for marking a packet as tunneled. */
    DP_PACKET_OL_TUNNEL_GENEVE = UINT16_C(1) << 11,
    DP_PACKET_OL_TUNNEL_VXLAN = UINT16_C(1) << 12,

#define DP_PACKET_OL_SHIFT_COUNT 16

    /* Inner offloads. */
    DP_PACKET_OL_INNER_IP_CKSUM_BAD =
        DP_PACKET_OL_IP_CKSUM_BAD << DP_PACKET_OL_SHIFT_COUNT,
    DP_PACKET_OL_INNER_IP_CKSUM_GOOD =
        DP_PACKET_OL_IP_CKSUM_GOOD << DP_PACKET_OL_SHIFT_COUNT,
    DP_PACKET_OL_INNER_L4_CKSUM_BAD =
        DP_PACKET_OL_L4_CKSUM_BAD << DP_PACKET_OL_SHIFT_COUNT,
    DP_PACKET_OL_INNER_L4_CKSUM_GOOD =
        DP_PACKET_OL_L4_CKSUM_GOOD << DP_PACKET_OL_SHIFT_COUNT,
    DP_PACKET_OL_INNER_L4_PROTO_TCP =
        DP_PACKET_OL_L4_PROTO_TCP << DP_PACKET_OL_SHIFT_COUNT,
    DP_PACKET_OL_INNER_L4_PROTO_UDP =
        DP_PACKET_OL_L4_PROTO_UDP << DP_PACKET_OL_SHIFT_COUNT,
};

#ifdef DPDK_NETDEV
BUILD_ASSERT_DECL(DP_PACKET_OL_IP_CKSUM_BAD == RTE_MBUF_F_RX_IP_CKSUM_BAD);
BUILD_ASSERT_DECL(DP_PACKET_OL_IP_CKSUM_GOOD == RTE_MBUF_F_RX_IP_CKSUM_GOOD);
BUILD_ASSERT_DECL(DP_PACKET_OL_L4_CKSUM_BAD == RTE_MBUF_F_RX_L4_CKSUM_BAD);
BUILD_ASSERT_DECL(DP_PACKET_OL_L4_CKSUM_GOOD == RTE_MBUF_F_RX_L4_CKSUM_GOOD);
#endif

#define DP_PACKET_OL_IP_CKSUM_MASK (DP_PACKET_OL_IP_CKSUM_GOOD \
                                    | DP_PACKET_OL_IP_CKSUM_BAD)
#define DP_PACKET_OL_L4_CKSUM_MASK (DP_PACKET_OL_L4_CKSUM_GOOD \
                                    | DP_PACKET_OL_L4_CKSUM_BAD)

#define DP_PACKET_OL_TUNNEL_MASK (DP_PACKET_OL_TUNNEL_GENEVE \
                                  | DP_PACKET_OL_TUNNEL_VXLAN)

#define DP_PACKET_OL_L4_PROTO_MASK (DP_PACKET_OL_L4_PROTO_TCP \
                                    | DP_PACKET_OL_L4_PROTO_UDP)

#define DP_PACKET_OL_INNER_IP_CKSUM_MASK (DP_PACKET_OL_INNER_IP_CKSUM_GOOD \
                                          | DP_PACKET_OL_INNER_IP_CKSUM_BAD)

#define DP_PACKET_OL_INNER_L4_CKSUM_MASK (DP_PACKET_OL_INNER_L4_CKSUM_GOOD \
                                          | DP_PACKET_OL_INNER_L4_CKSUM_BAD)

#define DP_PACKET_OL_INNER_L4_PROTO_MASK (DP_PACKET_OL_INNER_L4_PROTO_TCP \
                                          | DP_PACKET_OL_INNER_L4_PROTO_UDP)

/* Buffer for holding packet data.  A dp_packet is automatically reallocated
 * as necessary if it grows too large for the available memory.
 * By default the packet type is set to Ethernet (PT_ETH).
 */
struct dp_packet {
#ifdef DPDK_NETDEV
    struct rte_mbuf mbuf;       /* DPDK mbuf */
#else
    void *base_;                /* First byte of allocated space. */
    uint16_t allocated_;        /* Number of bytes allocated. */
    uint16_t data_ofs;          /* First byte actually in use. */
    uint32_t size_;             /* Number of bytes in use. */
    uint32_t rss_hash;          /* Packet hash. */
    uint32_t flow_mark;         /* Packet flow mark. */
    uint16_t tso_segsz;         /* TCP segment size. */
#endif
    enum dp_packet_source source;  /* Source of memory allocated as 'base'. */
    bool has_hash;                 /* Is the 'rss_hash' valid? */
    bool has_mark;                 /* Is the 'flow_mark' valid? */

    /* All the following elements of this struct are copied in a single call
     * of memcpy in dp_packet_clone_with_headroom. */
    uint16_t l2_pad_size;          /* Detected l2 padding size.
                                    * Padding is non-pullable. */
    uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
    uint16_t l3_ofs;               /* Network-level header offset,
                                    * or UINT16_MAX. */
    uint16_t l4_ofs;               /* Transport-level header offset,
                                      or UINT16_MAX. */
    uint16_t inner_l3_ofs;         /* Inner Network-level header offset,
                                    * or UINT16_MAX. */
    uint16_t inner_l4_ofs;         /* Inner Transport-level header offset,
                                      or UINT16_MAX. */
    uint32_t cutlen;               /* length in bytes to cut from the end. */
    ovs_be32 packet_type;          /* Packet type as defined in OpenFlow */
    enum OVS_PACKED_ENUM dp_packet_offload_mask offloads;
                                   /* Checksums status and offloads. */
    union {
        struct pkt_metadata md;
        uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
    };
};

BUILD_ASSERT_DECL(MEMBER_SIZEOF(struct dp_packet, offloads)
                  == sizeof(uint32_t));

#if HAVE_AF_XDP
struct dp_packet_afxdp {
    struct umem_pool *mpool;
    struct dp_packet packet;
};
#endif

static inline void *dp_packet_data(const struct dp_packet *);
static inline void dp_packet_set_data(struct dp_packet *, void *);
static inline void *dp_packet_base(const struct dp_packet *);
static inline void dp_packet_set_base(struct dp_packet *, void *);

static inline uint32_t dp_packet_size(const struct dp_packet *);
static inline void dp_packet_set_size(struct dp_packet *, uint32_t);

static inline uint16_t dp_packet_get_allocated(const struct dp_packet *);
static inline void dp_packet_set_allocated(struct dp_packet *, uint16_t);

static inline uint16_t dp_packet_get_tso_segsz(const struct dp_packet *);
static inline void dp_packet_set_tso_segsz(struct dp_packet *, uint16_t);

void *dp_packet_resize_l2(struct dp_packet *, int increment);
void *dp_packet_resize_l2_5(struct dp_packet *, int increment);
static inline void *dp_packet_eth(const struct dp_packet *);
static inline void dp_packet_reset_outer_offsets(struct dp_packet *);
static inline void dp_packet_reset_offsets(struct dp_packet *);
static inline void dp_packet_reset_offload(struct dp_packet *);
static inline uint16_t dp_packet_l2_pad_size(const struct dp_packet *);
static inline void dp_packet_set_l2_pad_size(struct dp_packet *, uint16_t);
static inline void *dp_packet_l2_5(const struct dp_packet *);
static inline void dp_packet_set_l2_5(struct dp_packet *, void *);
static inline void *dp_packet_l3(const struct dp_packet *);
static inline void dp_packet_set_l3(struct dp_packet *, void *);
static inline void *dp_packet_l4(const struct dp_packet *);
static inline void dp_packet_set_l4(struct dp_packet *, void *);
static inline size_t dp_packet_l4_size(const struct dp_packet *);
static inline const void *dp_packet_get_tcp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_udp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_sctp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_icmp_payload(const struct dp_packet *);
static inline const void *dp_packet_get_nd_payload(const struct dp_packet *);

void dp_packet_use(struct dp_packet *, void *, size_t);
void dp_packet_use_stub(struct dp_packet *, void *, size_t);
void dp_packet_use_const(struct dp_packet *, const void *, size_t);
#if HAVE_AF_XDP
void dp_packet_use_afxdp(struct dp_packet *, void *, size_t, size_t);
#endif
void dp_packet_init_dpdk(struct dp_packet *);

void dp_packet_init(struct dp_packet *, size_t);
void dp_packet_uninit(struct dp_packet *);

struct dp_packet *dp_packet_new(size_t);
struct dp_packet *dp_packet_new_with_headroom(size_t, size_t headroom);
struct dp_packet *dp_packet_clone(const struct dp_packet *);
struct dp_packet *dp_packet_clone_with_headroom(const struct dp_packet *,
                                                size_t headroom);
struct dp_packet *dp_packet_clone_data(const void *, size_t);
struct dp_packet *dp_packet_clone_data_with_headroom(const void *, size_t,
                                                     size_t headroom);
void dp_packet_resize(struct dp_packet *b, size_t new_headroom,
                      size_t new_tailroom);
static inline void dp_packet_delete(struct dp_packet *);
static inline void dp_packet_swap(struct dp_packet *, struct dp_packet *);

static inline void *dp_packet_at(const struct dp_packet *, size_t offset,
                                 size_t size);
static inline void *dp_packet_at_assert(const struct dp_packet *,
                                        size_t offset, size_t size);
static inline void *dp_packet_tail(const struct dp_packet *);
static inline void *dp_packet_end(const struct dp_packet *);

void *dp_packet_put_uninit(struct dp_packet *, size_t);
void *dp_packet_put_zeros(struct dp_packet *, size_t);
void *dp_packet_put(struct dp_packet *, const void *, size_t);
char *dp_packet_put_hex(struct dp_packet *, const char *s, size_t *n);
void dp_packet_reserve(struct dp_packet *, size_t);
void dp_packet_reserve_with_tailroom(struct dp_packet *, size_t headroom,
                                     size_t tailroom);
void *dp_packet_push_uninit(struct dp_packet *, size_t);
void *dp_packet_push_zeros(struct dp_packet *, size_t);
void *dp_packet_push(struct dp_packet *, const void *, size_t);

static inline size_t dp_packet_headroom(const struct dp_packet *);
static inline size_t dp_packet_tailroom(const struct dp_packet *);
void dp_packet_prealloc_headroom(struct dp_packet *, size_t);
void dp_packet_prealloc_tailroom(struct dp_packet *, size_t);
void dp_packet_shift(struct dp_packet *, int);

static inline void dp_packet_clear(struct dp_packet *);
static inline void *dp_packet_pull(struct dp_packet *, size_t);
static inline void *dp_packet_try_pull(struct dp_packet *, size_t);

void *dp_packet_steal_data(struct dp_packet *);

static inline bool dp_packet_equal(const struct dp_packet *,
                                   const struct dp_packet *);

bool dp_packet_compare_offsets(struct dp_packet *good,
                               struct dp_packet *test,
                               struct ds *err_str);
void dp_packet_ol_send_prepare(struct dp_packet *, uint64_t);


/* Frees memory that 'b' points to, as well as 'b' itself. */
static inline void
dp_packet_delete(struct dp_packet *b)
{
    if (b) {
        if (b->source == DPBUF_DPDK) {
            free_dpdk_buf(b);
            return;
        }

        if (b->source == DPBUF_AFXDP) {
            free_afxdp_buf(b);
            return;
        }

        dp_packet_uninit(b);
#ifdef DPDK_NETDEV
        free_cacheline(b);
#else
        free(b);
#endif
    }
}

/* Swaps content of two packets. */
static inline void
dp_packet_swap(struct dp_packet *a, struct dp_packet *b)
{
    ovs_assert(a->source == DPBUF_MALLOC || a->source == DPBUF_STUB);
    ovs_assert(b->source == DPBUF_MALLOC || b->source == DPBUF_STUB);
    struct dp_packet c = *a;

    *a = *b;
    *b = c;
}

/* If 'b' contains at least 'offset + size' bytes of data, returns a pointer to
 * byte 'offset'.  Otherwise, returns a null pointer. */
static inline void *
dp_packet_at(const struct dp_packet *b, size_t offset, size_t size)
{
    return offset + size <= dp_packet_size(b)
           ? (char *) dp_packet_data(b) + offset
           : NULL;
}

/* Returns a pointer to byte 'offset' in 'b', which must contain at least
 * 'offset + size' bytes of data. */
static inline void *
dp_packet_at_assert(const struct dp_packet *b, size_t offset, size_t size)
{
    ovs_assert(offset + size <= dp_packet_size(b));
    return ((char *) dp_packet_data(b)) + offset;
}

/* Returns a pointer to byte following the last byte of data in use in 'b'. */
static inline void *
dp_packet_tail(const struct dp_packet *b)
{
    return (char *) dp_packet_data(b) + dp_packet_size(b);
}

/* Returns a pointer to byte following the last byte allocated for use (but
 * not necessarily in use) in 'b'. */
static inline void *
dp_packet_end(const struct dp_packet *b)
{
    return (char *) dp_packet_base(b) + dp_packet_get_allocated(b);
}

/* Returns the number of bytes of headroom in 'b', that is, the number of bytes
 * of unused space in dp_packet 'b' before the data that is in use.  (Most
 * commonly, the data in a dp_packet is at its beginning, and thus the
 * dp_packet's headroom is 0.) */
static inline size_t
dp_packet_headroom(const struct dp_packet *b)
{
    return (char *) dp_packet_data(b) - (char *) dp_packet_base(b);
}

/* Returns the number of bytes that may be appended to the tail end of
 * dp_packet 'b' before the dp_packet must be reallocated. */
static inline size_t
dp_packet_tailroom(const struct dp_packet *b)
{
    return (char *) dp_packet_end(b) - (char *) dp_packet_tail(b);
}

/* Clears any data from 'b'. */
static inline void
dp_packet_clear(struct dp_packet *b)
{
    dp_packet_set_data(b, dp_packet_base(b));
    dp_packet_set_size(b, 0);
    dp_packet_reset_offsets(b);
    dp_packet_reset_offload(b);
}

/* Removes 'size' bytes from the head end of 'b', which must contain at least
 * 'size' bytes of data.  Returns the first byte of data removed. */
static inline void *
dp_packet_pull(struct dp_packet *b, size_t size)
{
    void *data = dp_packet_data(b);
    ovs_assert(dp_packet_size(b) - dp_packet_l2_pad_size(b) >= size);
    dp_packet_set_data(b, (char *) dp_packet_data(b) + size);
    dp_packet_set_size(b, dp_packet_size(b) - size);
    return data;
}

/* If 'b' has at least 'size' bytes of data, removes that many bytes from the
 * head end of 'b' and returns the first byte removed.  Otherwise, returns a
 * null pointer without modifying 'b'. */
static inline void *
dp_packet_try_pull(struct dp_packet *b, size_t size)
{
    return dp_packet_size(b) - dp_packet_l2_pad_size(b) >= size
        ? dp_packet_pull(b, size) : NULL;
}

static inline bool
dp_packet_equal(const struct dp_packet *a, const struct dp_packet *b)
{
    return dp_packet_size(a) == dp_packet_size(b) &&
           !memcmp(dp_packet_data(a), dp_packet_data(b), dp_packet_size(a));
}

static inline bool
dp_packet_is_eth(const struct dp_packet *b)
{
    return b->packet_type == htonl(PT_ETH);
}

/* Get the start of the Ethernet frame. 'l3_ofs' marks the end of the l2
 * headers, so return NULL if it is not set. */
static inline void *
dp_packet_eth(const struct dp_packet *b)
{
    return (dp_packet_is_eth(b) && b->l3_ofs != UINT16_MAX)
            ? dp_packet_data(b) : NULL;
}

/* Resets all outer layer offsets. */
static inline void
dp_packet_reset_outer_offsets(struct dp_packet *b)
{
    b->l2_pad_size = 0;
    b->l2_5_ofs = UINT16_MAX;
    b->l3_ofs = UINT16_MAX;
    b->l4_ofs = UINT16_MAX;
}

/* Resets all layer offsets.  'l3' offset must be set before 'l2' can be
 * retrieved. */
static inline void
dp_packet_reset_offsets(struct dp_packet *b)
{
    dp_packet_reset_outer_offsets(b);
    b->inner_l3_ofs = UINT16_MAX;
    b->inner_l4_ofs = UINT16_MAX;
}

static inline uint16_t
dp_packet_l2_pad_size(const struct dp_packet *b)
{
    return b->l2_pad_size;
}

static inline void
dp_packet_set_l2_pad_size(struct dp_packet *b, uint16_t pad_size)
{
    ovs_assert(pad_size <= dp_packet_size(b));
    b->l2_pad_size = pad_size;
}

static inline void *
dp_packet_l2_5(const struct dp_packet *b)
{
    return b->l2_5_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l2_5_ofs
           : NULL;
}

static inline void
dp_packet_set_l2_5(struct dp_packet *b, void *l2_5)
{
    b->l2_5_ofs = l2_5
                  ? (char *) l2_5 - (char *) dp_packet_data(b)
                  : UINT16_MAX;
}

static inline void *
dp_packet_l3(const struct dp_packet *b)
{
    return b->l3_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l3_ofs
           : NULL;
}

static inline void
dp_packet_set_l3(struct dp_packet *b, void *l3)
{
    b->l3_ofs = l3 ? (char *) l3 - (char *) dp_packet_data(b) : UINT16_MAX;
}

static inline void *
dp_packet_l4(const struct dp_packet *b)
{
    return b->l4_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->l4_ofs
           : NULL;
}

static inline void
dp_packet_set_l4(struct dp_packet *b, void *l4)
{
    b->l4_ofs = l4 ? (char *) l4 - (char *) dp_packet_data(b) : UINT16_MAX;
}

/* Returns the size of the packet from the beginning of the L3 header to the
 * end of the L3 payload.  Hence L2 padding is not included. */
static inline size_t
dp_packet_l3_size(const struct dp_packet *b)
{
    return OVS_LIKELY(b->l3_ofs != UINT16_MAX)
        ? (const char *)dp_packet_tail(b) - (const char *)dp_packet_l3(b)
        - dp_packet_l2_pad_size(b)
        : 0;
}

/* Returns the size of the packet from the beginning of the L4 header to the
 * end of the L4 payload.  Hence L2 padding is not included. */
static inline size_t
dp_packet_l4_size(const struct dp_packet *b)
{
    return OVS_LIKELY(b->l4_ofs != UINT16_MAX)
        ? (const char *)dp_packet_tail(b) - (const char *)dp_packet_l4(b)
        - dp_packet_l2_pad_size(b)
        : 0;
}

static inline void *
dp_packet_inner_l3(const struct dp_packet *b)
{
    return b->inner_l3_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->inner_l3_ofs
           : NULL;
}

static inline size_t
dp_packet_inner_l3_size(const struct dp_packet *b)
{
    return OVS_LIKELY(b->inner_l3_ofs != UINT16_MAX)
           ? (const char *) dp_packet_tail(b)
           - (const char *) dp_packet_inner_l3(b)
           - dp_packet_l2_pad_size(b)
           : 0;
}

static inline void *
dp_packet_inner_l4(const struct dp_packet *b)
{
    return b->inner_l4_ofs != UINT16_MAX
           ? (char *) dp_packet_data(b) + b->inner_l4_ofs
           : NULL;
}

static inline size_t
dp_packet_inner_l4_size(const struct dp_packet *b)
{
    return OVS_LIKELY(b->inner_l4_ofs != UINT16_MAX)
           ? (const char *) dp_packet_tail(b)
           - (const char *) dp_packet_inner_l4(b)
           - dp_packet_l2_pad_size(b)
           : 0;
}

static inline const void *
dp_packet_get_tcp_payload(const struct dp_packet *b)
{
    size_t l4_size = dp_packet_l4_size(b);

    if (OVS_LIKELY(l4_size >= TCP_HEADER_LEN)) {
        struct tcp_header *tcp = dp_packet_l4(b);
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

        if (OVS_LIKELY(tcp_len >= TCP_HEADER_LEN && tcp_len <= l4_size)) {
            return (const char *)tcp + tcp_len;
        }
    }
    return NULL;
}

static inline const void *
dp_packet_get_inner_tcp_payload(const struct dp_packet *b)
{
    size_t l4_size = dp_packet_inner_l4_size(b);

    if (OVS_LIKELY(l4_size >= TCP_HEADER_LEN)) {
        struct tcp_header *tcp = dp_packet_inner_l4(b);
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

        if (OVS_LIKELY(tcp_len >= TCP_HEADER_LEN && tcp_len <= l4_size)) {
            return (const char *) tcp + tcp_len;
        }
    }
    return NULL;
}

static inline uint32_t
dp_packet_get_tcp_payload_length(const struct dp_packet *pkt)
{
    const char *tcp_payload = dp_packet_get_tcp_payload(pkt);
    if (tcp_payload) {
        return ((char *) dp_packet_tail(pkt) - dp_packet_l2_pad_size(pkt)
                - tcp_payload);
    } else {
        return 0;
    }
}

static inline const void *
dp_packet_get_udp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= UDP_HEADER_LEN)
        ? (const char *)dp_packet_l4(b) + UDP_HEADER_LEN : NULL;
}

static inline const void *
dp_packet_get_sctp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= SCTP_HEADER_LEN)
        ? (const char *)dp_packet_l4(b) + SCTP_HEADER_LEN : NULL;
}

static inline const void *
dp_packet_get_icmp_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= ICMP_HEADER_LEN)
        ? (const char *)dp_packet_l4(b) + ICMP_HEADER_LEN : NULL;
}

static inline const void *
dp_packet_get_nd_payload(const struct dp_packet *b)
{
    return OVS_LIKELY(dp_packet_l4_size(b) >= ND_MSG_LEN)
        ? (const char *)dp_packet_l4(b) + ND_MSG_LEN : NULL;
}

#ifdef DPDK_NETDEV
static inline uint32_t *
dp_packet_rss_ptr(const struct dp_packet *b)
{
    return CONST_CAST(uint32_t *, &b->mbuf.hash.rss);
}

static inline uint32_t *
dp_packet_flow_mark_ptr(const struct dp_packet *b)
{
    return CONST_CAST(uint32_t *, &b->mbuf.hash.fdir.hi);
}

#else
static inline uint32_t *
dp_packet_rss_ptr(const struct dp_packet *b)
{
    return CONST_CAST(uint32_t *, &b->rss_hash);
}

static inline uint32_t *
dp_packet_flow_mark_ptr(const struct dp_packet *b)
{
    return CONST_CAST(uint32_t *, &b->flow_mark);
}
#endif

#ifdef DPDK_NETDEV
BUILD_ASSERT_DECL(offsetof(struct dp_packet, mbuf) == 0);

static inline void
dp_packet_init_specific(struct dp_packet *p)
{
    /* This initialization is needed for packets that do not come from DPDK
     * interfaces, when vswitchd is built with --with-dpdk. */
    p->mbuf.ol_flags = p->mbuf.tx_offload = p->mbuf.packet_type = 0;
    p->mbuf.nb_segs = 1;
    p->mbuf.next = NULL;
}

static inline void *
dp_packet_base(const struct dp_packet *b)
{
    return b->mbuf.buf_addr;
}

static inline void
dp_packet_set_base(struct dp_packet *b, void *d)
{
    b->mbuf.buf_addr = d;
}

static inline uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->mbuf.pkt_len;
}

static inline void
dp_packet_set_size(struct dp_packet *b, uint32_t v)
{
    /* netdev-dpdk does not currently support segmentation; consequently, for
     * all intents and purposes, 'data_len' (16 bit) and 'pkt_len' (32 bit) may
     * be used interchangably.
     *
     * On the datapath, it is expected that the size of packets
     * (and thus 'v') will always be <= UINT16_MAX; this means that there is no
     * loss of accuracy in assigning 'v' to 'data_len'.
     */

    ovs_assert(v <= UINT16_MAX);
    b->mbuf.data_len = (uint16_t)v;  /* Current seg length. */
    b->mbuf.pkt_len = v;             /* Total length of all segments linked to
                                      * this segment. */
}

static inline uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->mbuf.data_off;
}

static inline void
__packet_set_data(struct dp_packet *b, uint16_t v)
{
    b->mbuf.data_off = v;
}

static inline uint16_t
dp_packet_get_allocated(const struct dp_packet *b)
{
    return b->mbuf.buf_len;
}

static inline void
dp_packet_set_allocated(struct dp_packet *b, uint16_t s)
{
    b->mbuf.buf_len = s;
}

static inline uint16_t
dp_packet_get_tso_segsz(const struct dp_packet *p)
{
    return p->mbuf.tso_segsz;
}

static inline void
dp_packet_set_tso_segsz(struct dp_packet *p, uint16_t s)
{
    p->mbuf.tso_segsz = s;
}
#else /* DPDK_NETDEV */

static inline void
dp_packet_init_specific(struct dp_packet *p OVS_UNUSED)
{
    /* There are no implementation-specific fields for initialization. */
}

static inline void *
dp_packet_base(const struct dp_packet *b)
{
    return b->base_;
}

static inline void
dp_packet_set_base(struct dp_packet *b, void *d)
{
    b->base_ = d;
}

static inline uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->size_;
}

static inline void
dp_packet_set_size(struct dp_packet *b, uint32_t v)
{
    b->size_ = v;
}

static inline uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->data_ofs;
}

static inline void
__packet_set_data(struct dp_packet *b, uint16_t v)
{
    b->data_ofs = v;
}

static inline uint16_t
dp_packet_get_allocated(const struct dp_packet *b)
{
    return b->allocated_;
}

static inline void
dp_packet_set_allocated(struct dp_packet *b, uint16_t s)
{
    b->allocated_ = s;
}

static inline uint16_t
dp_packet_get_tso_segsz(const struct dp_packet *p)
{
    return p->tso_segsz;
}

static inline void
dp_packet_set_tso_segsz(struct dp_packet *p, uint16_t s)
{
    p->tso_segsz = s;
}
#endif /* DPDK_NETDEV */

static inline void
dp_packet_reset_cutlen(struct dp_packet *b)
{
    b->cutlen = 0;
}

static inline uint32_t
dp_packet_set_cutlen(struct dp_packet *b, uint32_t max_len)
{
    if (max_len < ETH_HEADER_LEN) {
        max_len = ETH_HEADER_LEN;
    }

    if (max_len >= dp_packet_size(b)) {
        b->cutlen = 0;
    } else {
        b->cutlen = dp_packet_size(b) - max_len;
    }
    return b->cutlen;
}

static inline uint32_t
dp_packet_get_cutlen(const struct dp_packet *b)
{
    /* Always in valid range if user uses dp_packet_set_cutlen. */
    return b->cutlen;
}

static inline uint32_t
dp_packet_get_send_len(const struct dp_packet *b)
{
    return dp_packet_size(b) - dp_packet_get_cutlen(b);
}

static inline void *
dp_packet_data(const struct dp_packet *b)
{
    return __packet_data(b) != UINT16_MAX
           ? (char *) dp_packet_base(b) + __packet_data(b) : NULL;
}

static inline void
dp_packet_set_data(struct dp_packet *b, void *data)
{
    if (data) {
        __packet_set_data(b, (char *) data - (char *) dp_packet_base(b));
    } else {
        __packet_set_data(b, UINT16_MAX);
    }
}

enum { NETDEV_MAX_BURST = 32 }; /* Maximum number packets in a batch. */

struct dp_packet_batch {
    size_t count;
    bool trunc; /* true if the batch needs truncate. */
    struct dp_packet *packets[NETDEV_MAX_BURST];
};

static inline void
dp_packet_batch_init(struct dp_packet_batch *batch)
{
    batch->count = 0;
    batch->trunc = false;
}

static inline void
dp_packet_batch_add__(struct dp_packet_batch *batch,
                      struct dp_packet *packet, size_t limit)
{
    if (batch->count < limit) {
        batch->packets[batch->count++] = packet;
    } else {
        dp_packet_delete(packet);
    }
}

/* When the batch is full, 'packet' will be dropped and freed. */
static inline void
dp_packet_batch_add(struct dp_packet_batch *batch, struct dp_packet *packet)
{
    dp_packet_batch_add__(batch, packet, NETDEV_MAX_BURST);
}

static inline size_t
dp_packet_batch_size(const struct dp_packet_batch *batch)
{
    return batch->count;
}

/* Clear 'batch' for refill. Use dp_packet_batch_refill() to add
 * packets back into the 'batch'. */
static inline void
dp_packet_batch_refill_init(struct dp_packet_batch *batch)
{
    batch->count = 0;
};

static inline void
dp_packet_batch_refill(struct dp_packet_batch *batch,
                       struct dp_packet *packet, size_t idx)
{
    dp_packet_batch_add__(batch, packet, MIN(NETDEV_MAX_BURST, idx + 1));
}

static inline void
dp_packet_batch_init_packet(struct dp_packet_batch *batch, struct dp_packet *p)
{
    dp_packet_batch_init(batch);
    batch->count = 1;
    batch->packets[0] = p;
}

static inline bool
dp_packet_batch_is_empty(const struct dp_packet_batch *batch)
{
    return !dp_packet_batch_size(batch);
}

static inline bool
dp_packet_batch_is_full(const struct dp_packet_batch *batch)
{
    return dp_packet_batch_size(batch) == NETDEV_MAX_BURST;
}

#define DP_PACKET_BATCH_FOR_EACH(IDX, PACKET, BATCH)                \
    for (size_t IDX = 0; IDX < dp_packet_batch_size(BATCH); IDX++)  \
        if (PACKET = (BATCH)->packets[IDX], true)

/* Use this macro for cases where some packets in the 'BATCH' may be
 * dropped after going through each packet in the 'BATCH'.
 *
 * For packets to stay in the 'BATCH', they need to be refilled back
 * into the 'BATCH' by calling dp_packet_batch_refill(). Caller owns
 * the packets that are not refilled.
 *
 * Caller needs to supply 'SIZE', that stores the current number of
 * packets in 'BATCH'. It is best to declare this variable with
 * the 'const' modifier since it should not be modified by
 * the iterator.  */
#define DP_PACKET_BATCH_REFILL_FOR_EACH(IDX, SIZE, PACKET, BATCH)       \
    for (dp_packet_batch_refill_init(BATCH), IDX=0; IDX < SIZE; IDX++)  \
         if (PACKET = (BATCH)->packets[IDX], true)

static inline void
dp_packet_batch_clone(struct dp_packet_batch *dst,
                      struct dp_packet_batch *src)
{
    struct dp_packet *packet;

    dp_packet_batch_init(dst);
    DP_PACKET_BATCH_FOR_EACH (i, packet, src) {
        if (i + 1 < dp_packet_batch_size(src)) {
            OVS_PREFETCH(src->packets[i + 1]);
        }

        uint32_t headroom = dp_packet_headroom(packet);
        struct dp_packet *pkt_clone;

        pkt_clone  = dp_packet_clone_with_headroom(packet, headroom);
        dp_packet_batch_add(dst, pkt_clone);
    }
    dst->trunc = src->trunc;
}

static inline void
dp_packet_delete_batch(struct dp_packet_batch *batch, bool should_steal)
{
    if (should_steal) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            dp_packet_delete(packet);
        }
        dp_packet_batch_init(batch);
    }
}

static inline void
dp_packet_batch_apply_cutlen(struct dp_packet_batch *batch)
{
    if (batch->trunc) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            dp_packet_set_size(packet, dp_packet_get_send_len(packet));
            dp_packet_reset_cutlen(packet);
        }
        batch->trunc = false;
    }
}

static inline void
dp_packet_batch_reset_cutlen(struct dp_packet_batch *batch)
{
    if (batch->trunc) {
        struct dp_packet *packet;

        DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
            dp_packet_reset_cutlen(packet);
        }
        batch->trunc = false;
    }
}

/* Returns the RSS hash of the packet 'p'.  Note that the returned value is
 * correct only if 'dp_packet_rss_valid(p)' returns 'true'. */
static inline uint32_t
dp_packet_get_rss_hash(const struct dp_packet *p)
{
    return *dp_packet_rss_ptr(p);
}

static inline void
dp_packet_set_rss_hash(struct dp_packet *p, uint32_t hash)
{
    *dp_packet_rss_ptr(p) = hash;
    p->has_hash = true;
}

static inline bool
dp_packet_rss_valid(const struct dp_packet *p)
{
    return p->has_hash;
}

static inline void
dp_packet_reset_offload(struct dp_packet *p)
{
    p->has_hash = p->has_mark = false;
    p->offloads = 0;
}

static inline bool
dp_packet_has_flow_mark(const struct dp_packet *p, uint32_t *mark)
{
    if (p->has_mark) {
        *mark = *dp_packet_flow_mark_ptr(p);
        return true;
    }

    return false;
}

static inline void
dp_packet_set_flow_mark(struct dp_packet *p, uint32_t mark)
{
    *dp_packet_flow_mark_ptr(p) = mark;
    p->has_mark = true;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_tunnel_geneve(const struct dp_packet *b)
{
    return (b->offloads & DP_PACKET_OL_TUNNEL_MASK)
           == DP_PACKET_OL_TUNNEL_GENEVE;
}

static inline void
dp_packet_tunnel_set_geneve(struct dp_packet *b)
{
    b->offloads &= ~DP_PACKET_OL_TUNNEL_VXLAN;
    b->offloads |= DP_PACKET_OL_TUNNEL_GENEVE;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_tunnel_vxlan(const struct dp_packet *b)
{
    return (b->offloads & DP_PACKET_OL_TUNNEL_MASK)
           == DP_PACKET_OL_TUNNEL_VXLAN;
}

static inline void
dp_packet_tunnel_set_vxlan(struct dp_packet *b)
{
    b->offloads &= ~DP_PACKET_OL_TUNNEL_GENEVE;
    b->offloads |= DP_PACKET_OL_TUNNEL_VXLAN;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_tunnel_gre(const struct dp_packet *b)
{
    return (b->offloads & DP_PACKET_OL_TUNNEL_MASK)
           == DP_PACKET_OL_TUNNEL_MASK;
}

static inline void
dp_packet_tunnel_set_gre(struct dp_packet *b)
{
    b->offloads |= DP_PACKET_OL_TUNNEL_MASK;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_tunnel(const struct dp_packet *b)
{
    return !!(b->offloads & DP_PACKET_OL_TUNNEL_MASK);
}

/* Marks packet 'p' with good IPv4 checksum. */
static inline void
dp_packet_ip_checksum_set_good(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_IP_CKSUM_BAD;
    p->offloads |= DP_PACKET_OL_IP_CKSUM_GOOD;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_ip_checksum_bad(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_IP_CKSUM_MASK)
            == DP_PACKET_OL_IP_CKSUM_BAD;
}

static inline void
dp_packet_ip_checksum_set_bad(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_IP_CKSUM_GOOD;
    p->offloads |= DP_PACKET_OL_IP_CKSUM_BAD;
}

/* Returns 'true' if the IPv4 header has good integrity but the
 * checksum in it is incomplete. */
static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_ip_checksum_partial(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_IP_CKSUM_MASK)
            == DP_PACKET_OL_IP_CKSUM_MASK;
}

/* Marks packet 'p' as having a valid IPv4 header, but no checksum. */
static inline void
dp_packet_ip_checksum_set_partial(struct dp_packet *p)
{
    p->offloads |= DP_PACKET_OL_IP_CKSUM_MASK;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_ip_checksum_unknown(const struct dp_packet *p)
{
    return !(p->offloads & DP_PACKET_OL_IP_CKSUM_MASK);
}

static inline void
dp_packet_ip_checksum_set_unknown(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_IP_CKSUM_MASK;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_ip_checksum_valid(const struct dp_packet *p)
{
    return !!(p->offloads & DP_PACKET_OL_IP_CKSUM_GOOD);
}

/* Marks packet 'p' with good inner IPv4 checksum. */
static inline void
dp_packet_inner_ip_checksum_set_good(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_INNER_IP_CKSUM_BAD;
    p->offloads |= DP_PACKET_OL_INNER_IP_CKSUM_GOOD;
}

/* Returns 'true' if the inner IPv4 header has good integrity but the
 * checksum in it is incomplete. */
static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_inner_ip_checksum_partial(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_INNER_IP_CKSUM_MASK)
            == DP_PACKET_OL_INNER_IP_CKSUM_MASK;
}

/* Marks packet 'p' as having a valid inner IPv4 header, but no checksum. */
static inline void
dp_packet_inner_ip_checksum_set_partial(struct dp_packet *p)
{
    p->offloads |= DP_PACKET_OL_INNER_IP_CKSUM_MASK;
}

/* Calculate and set the IPv4 header checksum in packet 'p'. */
static inline void
dp_packet_ip_set_header_csum(struct dp_packet *p, bool inner)
{
    struct ip_header *ip;
    size_t l3_size;
    size_t ip_len;

    if (inner) {
        ip = dp_packet_inner_l3(p);
        l3_size = dp_packet_inner_l3_size(p);
    } else {
        ip = dp_packet_l3(p);
        l3_size = dp_packet_l3_size(p);
    }

    ovs_assert(ip);

    ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

    if (OVS_LIKELY(ip_len >= IP_HEADER_LEN && ip_len < l3_size)) {
        ip->ip_csum = 0;
        ip->ip_csum = csum(ip, ip_len);
    }

    if (inner) {
        dp_packet_inner_ip_checksum_set_good(p);
    } else {
        dp_packet_ip_checksum_set_good(p);
    }
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_proto_tcp(const struct dp_packet *b)
{
    return (b->offloads & DP_PACKET_OL_L4_PROTO_MASK)
            == DP_PACKET_OL_L4_PROTO_TCP;
}

static inline void
dp_packet_l4_proto_set_tcp(struct dp_packet *b)
{
    b->offloads &= ~DP_PACKET_OL_L4_PROTO_UDP;
    b->offloads |= DP_PACKET_OL_L4_PROTO_TCP;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_proto_udp(const struct dp_packet *b)
{
    return (b->offloads & DP_PACKET_OL_L4_PROTO_MASK)
            == DP_PACKET_OL_L4_PROTO_UDP;
}

static inline void
dp_packet_l4_proto_set_udp(struct dp_packet *b)
{
    b->offloads &= ~DP_PACKET_OL_L4_PROTO_TCP;
    b->offloads |= DP_PACKET_OL_L4_PROTO_UDP;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_proto_sctp(const struct dp_packet *b)
{
    return (b->offloads & DP_PACKET_OL_L4_PROTO_MASK)
            == DP_PACKET_OL_L4_PROTO_MASK;
}

static inline void
dp_packet_l4_proto_set_sctp(struct dp_packet *b)
{
    b->offloads |= DP_PACKET_OL_L4_PROTO_MASK;
}

/* Returns 'true' if the packet 'p' has good integrity and the
 * checksum in it is correct. */
static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_checksum_good(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_L4_CKSUM_MASK)
            == DP_PACKET_OL_L4_CKSUM_GOOD;
}

/* Marks packet 'p' with good L4 checksum. */
static inline void
dp_packet_l4_checksum_set_good(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_L4_CKSUM_BAD;
    p->offloads |= DP_PACKET_OL_L4_CKSUM_GOOD;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_checksum_bad(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_L4_CKSUM_MASK)
            == DP_PACKET_OL_L4_CKSUM_BAD;
}

static inline void
dp_packet_l4_checksum_set_bad(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_L4_CKSUM_GOOD;
    p->offloads |= DP_PACKET_OL_L4_CKSUM_BAD;
}

/* Returns 'true' if the packet has good integrity though the
 * checksum in the packet 'p' is not complete. */
static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_checksum_partial(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_L4_CKSUM_MASK)
            == DP_PACKET_OL_L4_CKSUM_MASK;
}

/* Marks packet 'p' with good integrity though the checksum in the
 * packet is not complete. */
static inline void
dp_packet_l4_checksum_set_partial(struct dp_packet *p)
{
    p->offloads |= DP_PACKET_OL_L4_CKSUM_MASK;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_checksum_unknown(const struct dp_packet *p)
{
    return !(p->offloads & DP_PACKET_OL_L4_CKSUM_MASK);
}

static inline void
dp_packet_l4_checksum_set_unknown(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_L4_CKSUM_MASK;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_l4_checksum_valid(const struct dp_packet *p)
{
    return !!(p->offloads & DP_PACKET_OL_L4_CKSUM_GOOD);
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_inner_l4_proto_tcp(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_INNER_L4_PROTO_MASK)
            == DP_PACKET_OL_INNER_L4_PROTO_TCP;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_inner_l4_proto_udp(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_INNER_L4_PROTO_MASK)
            == DP_PACKET_OL_INNER_L4_PROTO_UDP;
}

static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_inner_l4_proto_sctp(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_INNER_L4_PROTO_MASK)
            == DP_PACKET_OL_INNER_L4_PROTO_MASK;
}

/* Returns 'true' if the inner L4 header has good integrity and the
 * checksum in it is complete. */
static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_inner_l4_checksum_good(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_INNER_L4_CKSUM_MASK)
            == DP_PACKET_OL_INNER_L4_CKSUM_GOOD;
}

/* Marks packet 'p' as having a valid inner l4 header, but no checksum. */
static inline void
dp_packet_inner_l4_checksum_set_good(struct dp_packet *p)
{
    p->offloads &= ~DP_PACKET_OL_INNER_L4_CKSUM_BAD;
    p->offloads |= DP_PACKET_OL_INNER_L4_CKSUM_GOOD;
}

/* Returns 'true' if the inner L4 header has good integrity but the
 * checksum in it is incomplete. */
static inline bool OVS_WARN_UNUSED_RESULT
dp_packet_inner_l4_checksum_partial(const struct dp_packet *p)
{
    return (p->offloads & DP_PACKET_OL_INNER_L4_CKSUM_MASK)
            == DP_PACKET_OL_INNER_L4_CKSUM_MASK;
}

/* Marks packet 'p' as having a valid inner l4 header, but no checksum. */
static inline void
dp_packet_inner_l4_checksum_set_partial(struct dp_packet *p)
{
    p->offloads |= DP_PACKET_OL_INNER_L4_CKSUM_MASK;
}

static inline void
dp_packet_reset_packet(struct dp_packet *b, int off)
{
    dp_packet_set_size(b, dp_packet_size(b) - off);
    dp_packet_set_data(b, ((unsigned char *) dp_packet_data(b) + off));
    dp_packet_reset_offsets(b);
}

static inline uint32_t ALWAYS_INLINE
dp_packet_calc_hash_ipv4(const uint8_t *pkt, const uint16_t l3_ofs,
                         uint32_t hash)
{
    const void *ipv4_src = &pkt[l3_ofs + offsetof(struct ip_header, ip_src)];
    const void *ipv4_dst = &pkt[l3_ofs + offsetof(struct ip_header, ip_dst)];
    uint32_t ip_src, ip_dst;

    memcpy(&ip_src, ipv4_src, sizeof ip_src);
    memcpy(&ip_dst, ipv4_dst, sizeof ip_dst);

    /* IPv4 Src and Dst. */
    hash = hash_add(hash, ip_src);
    hash = hash_add(hash, ip_dst);

    /* IPv4 proto. */
    hash = hash_add(hash, pkt[l3_ofs + offsetof(struct ip_header, ip_proto)]);

    return hash;
}

static inline void ALWAYS_INLINE
dp_packet_update_rss_hash_ipv4(struct dp_packet *packet)
{
    if (dp_packet_rss_valid(packet)) {
        return;
    }

    const uint8_t *pkt = dp_packet_data(packet);
    const uint16_t l3_ofs = packet->l3_ofs;
    uint32_t hash = 0;

    /* IPv4 Src, Dst and proto. */
    hash = dp_packet_calc_hash_ipv4(pkt, l3_ofs, hash);

    hash = hash_finish(hash, 42);
    dp_packet_set_rss_hash(packet, hash);
}

static inline void ALWAYS_INLINE
dp_packet_update_rss_hash_ipv4_tcp_udp(struct dp_packet *packet)
{
    if (dp_packet_rss_valid(packet)) {
        return;
    }

    const uint8_t *pkt = dp_packet_data(packet);
    const void *l4_ports = &pkt[packet->l4_ofs];
    const uint16_t l3_ofs = packet->l3_ofs;
    uint32_t hash = 0;
    uint32_t ports;

    /* IPv4 Src, Dst and proto. */
    hash = dp_packet_calc_hash_ipv4(pkt, l3_ofs, hash);

    /* L4 ports. */
    memcpy(&ports,  l4_ports, sizeof ports);
    hash = hash_add(hash, ports);

    hash = hash_finish(hash, 42);
    dp_packet_set_rss_hash(packet, hash);
}

static inline void ALWAYS_INLINE
dp_packet_update_rss_hash_ipv6_tcp_udp(struct dp_packet *packet)
{
    if (dp_packet_rss_valid(packet)) {
        return;
    }

    const uint8_t *pkt = dp_packet_data(packet);
    const uint16_t l3_ofs = packet->l3_ofs;
    uint32_t ipv6_src_off = offsetof(struct ovs_16aligned_ip6_hdr, ip6_src);
    uint32_t ipv6_dst_off = offsetof(struct ovs_16aligned_ip6_hdr, ip6_dst);
    uint32_t ipv6_proto_off = offsetof(struct ovs_16aligned_ip6_hdr,
                                       ip6_ctlun.ip6_un1.ip6_un1_nxt);
    const void *ipv6_src_l = &pkt[l3_ofs + ipv6_src_off];
    const void *ipv6_src_h = &pkt[l3_ofs + ipv6_src_off + 8];
    const void *ipv6_dst_l = &pkt[l3_ofs + ipv6_dst_off];
    const void *ipv6_dst_h = &pkt[l3_ofs + ipv6_dst_off + 8];
    const void *l4_ports = &pkt[packet->l4_ofs];
    uint64_t ipv6_src_lo, ipv6_src_hi;
    uint64_t ipv6_dst_lo, ipv6_dst_hi;
    uint32_t ports;
    uint32_t hash = 0;

    memcpy(&ipv6_src_lo, ipv6_src_l, sizeof ipv6_src_lo);
    memcpy(&ipv6_src_hi, ipv6_src_h, sizeof ipv6_src_hi);
    memcpy(&ipv6_dst_lo, ipv6_dst_l, sizeof ipv6_dst_lo);
    memcpy(&ipv6_dst_hi, ipv6_dst_h, sizeof ipv6_dst_hi);
    memcpy(&ports, l4_ports, sizeof ports);

    /* IPv6 Src and Dst. */
    hash = hash_add64(hash, ipv6_src_lo);
    hash = hash_add64(hash, ipv6_src_hi);
    hash = hash_add64(hash, ipv6_dst_lo);
    hash = hash_add64(hash, ipv6_dst_hi);
    /* IPv6 proto. */
    hash = hash_add(hash, pkt[l3_ofs + ipv6_proto_off]);
    /* L4 ports. */
    hash = hash_add(hash, ports);
    hash = hash_finish(hash, 42);

    dp_packet_set_rss_hash(packet, hash);
}

#ifdef  __cplusplus
}
#endif

#endif /* dp-packet.h */
