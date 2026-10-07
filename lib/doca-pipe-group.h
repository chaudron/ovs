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

#ifndef DOCA_PIPE_GROUP_H
#define DOCA_PIPE_GROUP_H

#include <doca_flow.h>

#include "cmap.h"
#include "netdev-doca.h"
#include "ovs-doca.h"

#include "openvswitch/list.h"
#include "openvswitch/thread.h"

struct doca_pipe_group_ctx;
struct doca_pipe_group_mask_ctx;

enum doca_pipe_group_type {
    DOCA_PIPE_GROUP_TYPE_NONE,
};

struct doca_entry_handle {
    struct doca_flow_pipe_entry *entry;
    struct doca_pipe_group_mask_ctx *mctx;
};

struct doca_pipe_group_ctx *
doca_pipe_group_ctx_ref(struct netdev *netdev,
                        odp_port_t vport,
                        enum doca_pipe_group_type group_type);

void
doca_pipe_group_ctx_unref(struct doca_pipe_group_ctx *group_ctx);

struct doca_flow_pipe *
doca_pipe_group_get_pipe(struct doca_pipe_group_ctx *group_ctx);

doca_error_t
doca_pipe_group_add_deh(struct netdev *netdev,
                        uint16_t qid,
                        odp_port_t vport,
                        enum doca_pipe_group_type group_type,
                        uint32_t priority,
                        const struct ovs_doca_flow_match *match,
                        struct ovs_doca_flow_match *match_mask,
                        struct ovs_doca_flow_actions *actions,
                        struct ovs_doca_flow_actions *actions_mask,
                        const struct doca_flow_action_descs *action_descs,
                        struct doca_flow_monitor *monitor,
                        const struct doca_flow_fwd *fwd,
                        struct doca_entry_handle *deh)
    OVS_EXCLUDED(mgmt_queue_lock);

doca_error_t
doca_pipe_group_del_deh(struct netdev *netdev,
                        uint16_t qid,
                        struct doca_entry_handle *deh)
    OVS_EXCLUDED(mgmt_queue_lock);

void
doca_pipe_group_init(struct netdev *netdev);

void
doca_pipe_group_uninit(struct netdev *netdev);

#endif /* DOCA_PIPE_GROUP_H */
