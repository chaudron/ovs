/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef DPDK_H
#define DPDK_H

#include <stdbool.h>
#include <compiler.h>

#ifdef DPDK_NETDEV

#include <rte_config.h>
#include <rte_lcore.h>
#include <rte_ring.h>

#define NON_PMD_CORE_ID LCORE_ID_ANY

static inline ALWAYS_INLINE unsigned int
dpdk_ring_enqueue_zc_bulk_elem_start(struct rte_ring *r, unsigned int esize,
                                     unsigned int n,
                                     struct rte_ring_zc_data *zcd,
                                     unsigned int *free_space) {
    return rte_ring_enqueue_zc_bulk_elem_start(r, esize, n, zcd, free_space);
}

static inline ALWAYS_INLINE void
dpdk_ring_enqueue_zc_elem_finish(struct rte_ring *r, unsigned int n)
{
    rte_ring_enqueue_zc_elem_finish(r, n);
}

static inline ALWAYS_INLINE unsigned int
dpdk_ring_dequeue_zc_burst_elem_start(struct rte_ring *r, unsigned int esize,
                                      unsigned int n,
                                      struct rte_ring_zc_data *zcd,
                                      unsigned int *available)
{
    return rte_ring_dequeue_zc_burst_elem_start(r, esize, n, zcd, available);
}

static inline ALWAYS_INLINE void
dpdk_ring_dequeue_zc_finish(struct rte_ring *r, unsigned int n)
{
    return rte_ring_dequeue_zc_finish(r, n);
}

static inline ALWAYS_INLINE int
dpdk_ring_empty(const struct rte_ring *r)
{
    return rte_ring_empty(r);
}

static inline ALWAYS_INLINE unsigned int
dpdk_ring_count(const struct rte_ring *r)
{
    return rte_ring_count(r);
}

#else

#define NON_PMD_CORE_ID UINT32_MAX
#define RING_F_SC_DEQ     0x02
#define RING_F_MP_HTS_ENQ 0x20

struct rte_ring {
};

struct rte_ring_zc_data {
    void *ptr1;
    void *ptr2;
    unsigned int n1;
};

static inline ALWAYS_INLINE unsigned int
dpdk_ring_enqueue_zc_bulk_elem_start(struct rte_ring *r OVS_UNUSED,
                                     unsigned int esize OVS_UNUSED,
                                     unsigned int n OVS_UNUSED,
                                     struct rte_ring_zc_data *zcd OVS_UNUSED,
                                     unsigned int *free_space OVS_UNUSED) {
    return 0;
}

static inline ALWAYS_INLINE void
dpdk_ring_enqueue_zc_elem_finish(struct rte_ring *r OVS_UNUSED,
                                 unsigned int n OVS_UNUSED)
{
}

static inline ALWAYS_INLINE unsigned int
dpdk_ring_dequeue_zc_burst_elem_start(struct rte_ring *r OVS_UNUSED,
                                      unsigned int esize OVS_UNUSED,
                                      unsigned int n OVS_UNUSED,
                                      struct rte_ring_zc_data *zcd OVS_UNUSED,
                                      unsigned int *available OVS_UNUSED)
{
    return 0;
}

static inline ALWAYS_INLINE void
dpdk_ring_dequeue_zc_finish(struct rte_ring *r OVS_UNUSED,
                            unsigned int n OVS_UNUSED)
{
}

static inline ALWAYS_INLINE int
dpdk_ring_empty(const struct rte_ring *r OVS_UNUSED)
{
    return false;
}

static inline ALWAYS_INLINE unsigned int
dpdk_ring_count(const struct rte_ring *r OVS_UNUSED)
{
    return 0;
}

#endif /* DPDK_NETDEV */

struct smap;
struct ovsrec_open_vswitch;

void dpdk_init(const struct smap *ovs_other_config);
bool dpdk_attach_thread(unsigned cpu, bool assist_thread);
void dpdk_detach_thread(bool assist_thread);
bool dpdk_available(void);
void print_dpdk_version(void);
void dpdk_status(const struct ovsrec_open_vswitch *);
struct rte_ring *
dpdk_ring_create_elem(const char *name, unsigned int esize, unsigned int count,
                      unsigned int flags);
void dpdk_ring_free(struct rte_ring *r);

#endif /* dpdk.h */
