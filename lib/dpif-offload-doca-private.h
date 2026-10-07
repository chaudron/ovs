/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef DPIF_OFFLOAD_DOCA_PRIVATE_H
#define DPIF_OFFLOAD_DOCA_PRIVATE_H

#include <config.h>

#include "dp-packet.h"
#include "netlink-protocol.h"
#include "refmap.h"

#include "openvswitch/match.h"
#include "openvswitch/types.h"

/* Forward declarations of private structures. */
struct doca_offload;
struct netdev;

struct doca_offload_esw_data {
    struct refmap *group_rfm;
    struct refmap *group_mask_rfm;
};

enum {
    DOCA_OFFLOAD_PRIORITY_HIGH,
    DOCA_OFFLOAD_PRIORITY_MED,
    DOCA_OFFLOAD_PRIORITY_LOW,
};

/* DPIF offload doca implementation-specific functions.  These should only be
 * used by the associated netdev offload provider, i.e.,
 * dpif-offload-doca-netdev. */
unsigned int doca_offload_thread_id(void);
void doca_offload_unreference(struct doca_offload *offload, unsigned pmd_id,
                              void *flow_reference);
struct netdev *doca_offload_get_netdev(const struct doca_offload *,
                                       odp_port_t port_no);
void doca_offload_traverse_ports(
    const struct doca_offload *offload,
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux);

/* dpif-offload-doca-netdev specific offload functions.  These should only be
 * used by the associated dpif offload provider, i.e., dpif-offload-doca. */
int doca_netdev_offload_init(struct netdev *,
                             unsigned int offload_thread_count);
void doca_netdev_offload_uninit(struct netdev *);
int doca_netdev_flow_flush(struct doca_offload *, struct netdev *);
uint64_t doca_netdev_flow_count(struct netdev *,
                                unsigned int offload_thread_count);
uint64_t doca_netdev_flow_count_by_thread(struct netdev *, unsigned int tid);
int doca_netdev_hw_miss_packet_recover(struct doca_offload *, struct netdev *,
                                       unsigned pmd_id, struct dp_packet *,
                                       void **flow_reference);
int doca_netdev_flow_put(struct doca_offload *, unsigned pmd_id,
                         void *flow_reference, struct netdev *, struct match *,
                         struct nlattr *actions, size_t actions_len,
                         const ovs_u128 *ufid, odp_port_t orig_in_port,
                         void **previous_flow_reference,
                         struct dpif_flow_stats *);
int doca_netdev_flow_del(struct doca_offload *, struct netdev *,
                         unsigned pmd_id, const ovs_u128 *ufid,
                         void *flow_reference, struct dpif_flow_stats *);
int doca_netdev_flow_get(struct netdev *, struct match *,
                         struct nlattr **actions, const ovs_u128 *ufid,
                         struct dpif_flow_stats *, struct dpif_flow_attrs *,
                         struct ofpbuf *buf);
void doca_netdev_offload_start(struct netdev *netdev);
void doca_netdev_offload_stop(struct netdev *netdev);

#endif /* DPIF_OFFLOAD_DOCA_PRIVATE_H */
