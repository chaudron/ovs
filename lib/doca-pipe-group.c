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

#include <config.h>

#include "doca-pipe-group.h"

#include <sys/types.h>

#include <doca_flow.h>

#include "dpif.h"
#include "dpif-offload-doca-private.h"
#include "dp-packet.h"
#include "odp-util.h"
#include "ovs-doca.h"
#include "netdev-doca.h"
#include "netdev-vport.h"
#include "refmap.h"
#include "unixctl.h"
#include "util.h"

#include "openvswitch/vlog.h"
#include "openvswitch/list.h"

VLOG_DEFINE_THIS_MODULE(doca_pipe_group);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Design of the doca pipe groups and doca pipe group masks:
 *
 *  +-----------------+
 *  | Rule outside of |
 *  | group X pointing|
 *  | to it           |
 *  +------+----------+
 *         |
 *         |
 *         |                Group X
 *  +------------------------------------------------------+
 *  |      |                                               |
 *  |      |     +--->----+ Prio 0                         |
 *  |      |     ^  +----------------------+               |
 *  |      |     |  |     |                |               |
 *  |      |     |  |     +---+            |               |
 *  |      |     |  |         |            |               |
 *  |      v     |  | Mask A  v            |               |
 *  |   Group    |  | +-------+---------+  |     Group     |
 *  |   Start    ^  | |      Rule       |  |     End       |
 *  |   Anchor   |  | |      Rule       |  |     Anchor    |
 *  | +-------+  |  | |      Rule       |  |   +-------+   |
 *  | | Empty |  |  | |      Rule       |  |   | Empty |   |  Doca
 *  | | Basic |  ^  | +-------+---------+  |   | Basic +----> Offloads
 *  | | Pipe  |  |  |         |            |   | Pipe  |   |  Miss Path
 *  | +--+----+  |  |         |Miss FWD    |   +--+----+   |  Pipe
 *  |    |       |  |         |            |         ^     |
 *  |    |       |  | Mask B  v            |         |     |
 *  |    +--->---+  | +-------+---------+  |         |     |
 *  |    Miss FWD   | |      Rule       |  |         |     |
 *  |               | |      Rule       |  |         |     |
 *  |               | |      Rule       |  |         |     |
 *  |               | |      Rule       |  |         |     |
 *  |               | +-------+---------+  |         ^     |
 *  |               |         |            |         |     |
 *  |               +----------------------+         |     |
 *  |                         |                      |     |
 *  |                         +----->----------------+     |
 *  |                            Miss FWD                  |
 *  +------------------------------------------------------+ */

struct doca_pipe_group_ctx {
    struct doca_flow_pipe *start_anchor;
    struct doca_flow_pipe *end_anchor;
    struct ovs_list list;
    struct ovs_mutex lock;
    struct netdev *esw_netdev;
    bool is_root;
    char *name;
};

struct doca_pipe_group_key {
    odp_port_t vport;
    enum doca_pipe_group_type group_type;
};

struct doca_pipe_group_arg {
    struct doca_pipe_group_key k;
    struct doca_flow_pipe *start_anchor;
    struct netdev *netdev;
};

struct doca_pipe_group_mask_ctx {
    struct doca_pipe_group_ctx *group_ctx;
    struct doca_flow_pipe *pipe;
    uint32_t priority;
    struct ovs_list list;
    uint16_t qid;
    char *match_str;
    char *actions_str;
    uint32_t pipe_size;
    char *name;
};

struct doca_pipe_group_mask_key {
    uint32_t priority;
    char pad[4];
    struct doca_pipe_group_ctx *group_ctx;
    struct ovs_doca_flow_match match_mask;
    struct ovs_doca_flow_match match_value;
    struct ovs_doca_flow_actions actions_mask;
    struct ovs_doca_flow_actions actions_value;
    struct doca_flow_action_desc desc;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    uint32_t encap_type;
    uint32_t encap_size;
};

struct doca_pipe_group_mask_arg {
    struct doca_pipe_group_mask_key *key;
    struct netdev *netdev;
    struct ds match_ds;
    struct ds actions_ds;
    uint64_t allowed_queues_bitmap;
};

/* DOCA has three types of fields in the pipe match value, see below: */
enum doca_field_type {
    DOCA_FIELD_TYPE_IGNORED,
    /**< ignored field type - not matched. */
    DOCA_FIELD_TYPE_SPECIFIC,
    /**< specific field type - constant match for all pipe entries. */
    DOCA_FIELD_TYPE_CHANGEABLE,
    /**< changeable field type - match determined by entry value and pipe
     * match mask. */
};

static void
doca_pipe_group_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED);

static enum
doca_field_type field_get_type(const void *field_ptr, uint16_t field_len)
{
    uint16_t changeable_bytes, ignored_bytes;
    const uint8_t *data_array;

    data_array = (uint8_t *) field_ptr;
    ignored_bytes = 0;
    changeable_bytes = 0;

    for (uint16_t i = 0; i < field_len; i++) {
        if (data_array[i] == 0) {
            ignored_bytes++;
        } else if (data_array[i] == 0xFF) {
            changeable_bytes++;
        } else {
            return DOCA_FIELD_TYPE_SPECIFIC;
        }

        if (unlikely(ignored_bytes > 0 && changeable_bytes > 0)) {
            return DOCA_FIELD_TYPE_SPECIFIC;
        }
    }

    if (changeable_bytes > 0) {
        return DOCA_FIELD_TYPE_CHANGEABLE;
    }

    return DOCA_FIELD_TYPE_IGNORED;
}

static uint32_t
get_pipe_size(struct doca_pipe_group_ctx *group_ctx OVS_UNUSED)
{
    return 1024;
}

static doca_error_t
doca_pipe_group_create_anchor_pipe(struct netdev *netdev, char *pipe_name,
                                   struct doca_flow_pipe *next_pipe,
                                   struct doca_flow_pipe **anchor_pipe)
{
    struct doca_flow_fwd miss_fwd;
    doca_error_t ret;

    memset(&miss_fwd, 0, sizeof miss_fwd);
    if (next_pipe) {
        miss_fwd.type = DOCA_FLOW_FWD_PIPE;
        miss_fwd.next_pipe = next_pipe;

    } else {
        miss_fwd.type = DOCA_FLOW_FWD_DROP;
    }

    ret = ovs_doca_pipe_create(netdev, NULL, NULL, NULL, NULL, NULL, NULL,
                               NULL, &miss_fwd, 0, false, false, 0, pipe_name,
                               anchor_pipe);

    return ret;
}

static const char *
group_type_str(enum doca_pipe_group_type group_type)
{
    switch (group_type) {
    case DOCA_PIPE_GROUP_TYPE_NONE:
        return "none";
    }

    return "ERR";
}

static uint32_t
doca_pipe_group_name_vport(odp_port_t vport)
{
    return vport == ODPP_NONE ? 0 : vport;
}

static int
doca_pipe_group_ctx_init(void *ctx_, void *arg_)
{
    struct doca_pipe_group_ctx *group_ctx = ctx_;
    struct doca_flow_pipe *end_anchor_next_pipe;
    char pipe_name[OVS_DOCA_MAX_PIPE_NAME_LEN];
    struct doca_pipe_group_arg *arg = arg_;
    struct netdev_doca *dev;
    struct netdev *netdev;
    int ret;

    dev = netdev_doca_cast(arg->netdev);

    group_ctx->is_root = !!arg->start_anchor;
    group_ctx->esw_netdev = dev->esw_ctx->esw_netdev;
    netdev = group_ctx->esw_netdev;
    group_ctx->name = xasprintf("v%"PRIu32"-%s",
                                doca_pipe_group_name_vport(arg->k.vport),
                                group_type_str(arg->k.group_type));
    VLOG_DBG_RL(&rl, "%s: %p: %s", __FUNCTION__, group_ctx, group_ctx->name);

    ovs_list_init(&group_ctx->list);
    ovs_mutex_init(&group_ctx->lock);

    snprintf(pipe_name, sizeof pipe_name, "%s-EA", group_ctx->name);
    end_anchor_next_pipe = dev->esw_ctx->pre_miss_pipe;

    ret = doca_pipe_group_create_anchor_pipe(netdev, pipe_name,
                                             end_anchor_next_pipe,
                                             &group_ctx->end_anchor);
    if (ret) {
        VLOG_ERR("Failed to create %s: %d (%s)", pipe_name, ret,
                 doca_error_get_descr(ret));
        goto err_end_anchor;
    }

    VLOG_DBG_RL(&rl, "%s: end_anchor=%p ->%p", pipe_name,
                group_ctx->end_anchor, end_anchor_next_pipe);

    if (arg->start_anchor) {
        struct doca_flow_fwd miss_fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = group_ctx->end_anchor,
        };

        ret = doca_flow_pipe_update_miss(arg->start_anchor, &miss_fwd);
        if (ret) {
            VLOG_ERR("%s: Failed to update root start-anchor miss: %d (%s)",
                     netdev_get_name(netdev), ret,
                     doca_error_get_descr(ret));
            goto err_start_anchor;
        }

        VLOG_DBG_RL(&rl, "miss update: root start-anchor=%p, pipe=%p ->%p",
                    arg->start_anchor, end_anchor_next_pipe,
                    miss_fwd.next_pipe);
        group_ctx->start_anchor = arg->start_anchor;
    } else {
        snprintf(pipe_name, sizeof pipe_name, "%s-SA", group_ctx->name);
        ret = doca_pipe_group_create_anchor_pipe(netdev, pipe_name,
                                                 group_ctx->end_anchor,
                                                 &group_ctx->start_anchor);
        if (ret) {
            VLOG_ERR("Failed to create %s: %d (%s)", pipe_name, ret,
                     doca_error_get_descr(ret));
            goto err_start_anchor;
        }
    }

    VLOG_DBG_RL(&rl, "%s: start_anchor=%p ->%p", pipe_name,
                group_ctx->start_anchor, group_ctx->end_anchor);

    return 0;

err_start_anchor:
    doca_flow_pipe_destroy(group_ctx->end_anchor);
err_end_anchor:
    free(group_ctx->name);
    return ret;
}

static void
doca_pipe_group_ctx_uninit(void *ctx_)
{
    struct doca_pipe_group_ctx *group_ctx = ctx_;
    doca_error_t ret;

    VLOG_DBG_RL(&rl, "%s: %p: %s", __FUNCTION__, group_ctx, group_ctx->name);

    ovs_mutex_destroy(&group_ctx->lock);
    if (group_ctx->is_root) {
        struct netdev_doca *dev = netdev_doca_cast(group_ctx->esw_netdev);
        struct doca_flow_fwd miss_fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = dev->esw_ctx->pre_miss_pipe,
        };

        ret = doca_flow_pipe_update_miss(group_ctx->start_anchor, &miss_fwd);
        if (ret) {
            VLOG_ERR("%s: Failed to update root start-anchor miss: %d (%s)",
                     netdev_get_name(group_ctx->esw_netdev), ret,
                     doca_error_get_descr(ret));
        }
    } else {
        doca_flow_pipe_destroy(group_ctx->start_anchor);
    }

    doca_flow_pipe_destroy(group_ctx->end_anchor);
    free(group_ctx->name);
}

static struct ds *
doca_pipe_group_ctx_dump(struct ds *s, void *key_ OVS_UNUSED, void *ctx)
{
    struct doca_pipe_group_ctx *group_ctx = ctx;

    ds_put_format(s, "%s", group_ctx->name);

    return s;
}

struct doca_pipe_group_ctx *
doca_pipe_group_ctx_ref(struct netdev *netdev,
                        odp_port_t vport,
                        enum doca_pipe_group_type group_type)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct doca_offload_esw_data *offload_data =
        netdev_doca_get_esw_offload_data(netdev);
    struct doca_pipe_group_key key = {
        .vport = vport,
        .group_type = group_type,
    };
    struct doca_pipe_group_arg arg = {
        .k = key,
        .netdev = netdev,
    };

    if (vport == ODPP_NONE && group_type == DOCA_PIPE_GROUP_TYPE_NONE) {
        arg.start_anchor = dev->esw_ctx->root_pipe;
    }

    return refmap_ref(offload_data->group_rfm, &key, &arg);
}

void
doca_pipe_group_ctx_unref(struct doca_pipe_group_ctx *group_ctx)
{
    struct doca_offload_esw_data *offload_data;

    if (!group_ctx) {
        return;
    }

    offload_data = netdev_doca_get_esw_offload_data(group_ctx->esw_netdev);
    refmap_unref(offload_data->group_rfm, group_ctx);
}

struct doca_flow_pipe *
doca_pipe_group_get_pipe(struct doca_pipe_group_ctx *group_ctx)
{
    return group_ctx->start_anchor;
}

static void
doca_pipe_group_put_match_field_to_ds(struct ds *ds, char *prefix, char *field,
                                      unsigned char *value,
                                      unsigned char *mask,
                                      size_t size)
{
    enum doca_field_type type = field_get_type(value, size);

    if (type == DOCA_FIELD_TYPE_IGNORED) {
         return;
    }

    ds_put_format(ds, "%s.%s[%d,%s]=", prefix, field, (int) size,
                 type == DOCA_FIELD_TYPE_CHANGEABLE
                 ? "changeable"
                 : "specific");

    ds_put_cstr(ds, "0x");
    for (size_t i = 0; i < size; i++) {
        ds_put_format(ds, "%02x", value[i]);
    }

    ds_put_format(ds, "/");

    ds_put_cstr(ds, "0x");
    for (size_t i = 0; i < size; i++) {
        ds_put_format(ds, "%02x", mask[i]);
    }

    ds_put_format(ds, ", ");
}

#define log_field(field)                                                     \
    doca_pipe_group_put_match_field_to_ds(ds, prefix, #field,                \
                                          (unsigned char *) &value->field,   \
                                          (unsigned char *) &used->field,    \
                                          sizeof(value->field))

/* Verify a field is either ignored, or specifically matched, and set it in
 * used match as to mark that it was handled (so we can assert that no new
 * fields were missed). */
#define verify_specific_field(field)                                         \
    do {                                                                     \
        size_t __size = sizeof value->field;                                 \
        enum doca_field_type __type = field_get_type(&value->field, __size); \
        char *__used =                                                       \
            ((char *) used) +                                                \
            (size_t) (((char *) &value->field) -                             \
            ((char *) value));                                               \
                                                                             \
        /* Must be ignored or specific */                                    \
        ovs_assert(__type != DOCA_FIELD_TYPE_CHANGEABLE);                    \
        log_field(field);                                                    \
        memset(__used, 0, __size);                                           \
    } while (0)

/* Same as above, but class id is special as it's always specific even if its
 * all 0xFF.. */
#define verify_specific_field_class_id(field)                                \
    do {                                                                     \
        size_t __size = sizeof value->field;                                 \
        char *__used =                                                       \
            ((char *) used) +                                                \
            (size_t) (((char *) &value->field) -                             \
            ((char *) value));                                               \
                                                                             \
        log_field(field);                                                    \
        memset(__used, 0, __size);                                           \
    } while (0)

/* Same as above, just with a pointer to field instead of a field name. */
#define mark_specific_field_ptr(field_ptr)                                   \
    do {                                                                     \
        size_t __size = sizeof value->field;                                 \
        enum doca_field_type __type = field_get_type(&value->field, __size); \
        char *__used =                                                       \
            ((char *) used) +                                                \
            (size_t) (((char *) &value->field) -                             \
            ((char *) value));                                               \
                                                                             \
        /* Must be ignored or specific */                                    \
        ovs_assert(__type != DOCA_FIELD_TYPE_CHANGEABLE);                    \
        log_field(field);                                                    \
        memset(__used, 0, __size);                                           \
    } while (0)

/* Extend specifically matched fields masks so they will be considered
 * CHANGEABLE by doca and set it in used match as to mark that it was handled.
 * (so we can assert that no new fields were missed). */
#define extend_field_to_changeable(field)                                    \
    do {                                                                     \
        size_t __size = sizeof value->field;                                 \
        enum doca_field_type __type = field_get_type(&mask->field, __size);  \
        char *__used =                                                       \
            ((char *) used) +                                                \
            (size_t) (((char *) &value->field) -                             \
            ((char *) value));                                               \
                                                                             \
        /* If field isn't ignored, set field as changeable. */               \
        if (__type != DOCA_FIELD_TYPE_IGNORED) {                             \
            memset(&value->field, 0xFF, __size);                             \
        }                                                                    \
        log_field(field);                                                    \
        memset(__used, 0, __size);                                           \
    } while (0)

/* The following functions take in a match mask (or action mask), and from
 * it create a pipe match (value) where fields that can be CHANGEABLE will be
 * CHANGEABLE by extending the pipe match value to the full field size.
 * They also verify we didn't miss and new fields that might have been added.
 */
static void
mask_to_changeable_value_header_format(struct ds *ds, char *prefix,
                                       struct doca_flow_header_format *value,
                                       struct doca_flow_header_format *mask,
                                       struct doca_flow_header_format *used,
                                       enum doca_flow_tun_type encap_tun_type)
{
    /* Doca enforces this field to be specific for tunnel encap. */
    if (encap_tun_type) {
        mask->eth.type = 0;
        verify_specific_field(eth.type);
    } else {
        extend_field_to_changeable(eth.type);
    }

    extend_field_to_changeable(eth.dst_mac);
    extend_field_to_changeable(eth.src_mac);

    verify_specific_field(l2_valid_headers);
    if (value->l2_valid_headers & DOCA_FLOW_L2_VALID_HEADER_VLAN_0) {
        extend_field_to_changeable(eth_vlan[0]);
    }

    verify_specific_field(l3_type);
    if (value->l3_type == DOCA_FLOW_L3_TYPE_IP4) {
        extend_field_to_changeable(ip4.src_ip);
        extend_field_to_changeable(ip4.dst_ip);
        extend_field_to_changeable(ip4.dscp_ecn);
        extend_field_to_changeable(ip4.next_proto);
        extend_field_to_changeable(ip4.ttl);
    } else if (value->l3_type == DOCA_FLOW_L3_TYPE_IP6) {
        extend_field_to_changeable(ip6.src_ip);
        extend_field_to_changeable(ip6.dst_ip);
        extend_field_to_changeable(ip6.traffic_class);
        extend_field_to_changeable(ip6.next_proto);
        extend_field_to_changeable(ip6.hop_limit);
    }

    verify_specific_field(l4_type_ext);
    switch (value->l4_type_ext) {
    case DOCA_FLOW_L4_TYPE_EXT_TCP:
        extend_field_to_changeable(tcp.l4_port.src_port);
        extend_field_to_changeable(tcp.l4_port.dst_port);
        extend_field_to_changeable(tcp.flags);
        break;
    case DOCA_FLOW_L4_TYPE_EXT_UDP:
        extend_field_to_changeable(udp.l4_port.src_port);
        if (encap_tun_type == DOCA_FLOW_TUN_GENEVE) {
            /* Doca enforces specific geneve dst port. */
            mask->udp.l4_port.dst_port = 0;
            verify_specific_field(udp.l4_port.dst_port);
        } else {
            extend_field_to_changeable(udp.l4_port.dst_port);
        }

        break;
    case DOCA_FLOW_L4_TYPE_EXT_ICMP:
    case DOCA_FLOW_L4_TYPE_EXT_ICMP6:
        extend_field_to_changeable(icmp.type);
        extend_field_to_changeable(icmp.code);
        break;

    case DOCA_FLOW_L4_TYPE_EXT_TRANSPORT:
    case DOCA_FLOW_L4_TYPE_EXT_ROCE_V2:
    case DOCA_FLOW_L4_TYPE_EXT_NONE:
        break;
    }
}

static void
mask_to_changeable_value_tun(struct ds *ds, char *prefix,
                             struct doca_flow_tun *value,
                             struct doca_flow_tun *mask,
                             struct doca_flow_tun *used)
{
    union doca_flow_geneve_option *opt;

    verify_specific_field(type);
    switch (value->type) {
    case DOCA_FLOW_TUN_NONE:
    case DOCA_FLOW_TUN_MAX:
    case DOCA_FLOW_TUN_GTPU:
    case DOCA_FLOW_TUN_ESP:
    case DOCA_FLOW_TUN_MPLS_O_UDP:
    case DOCA_FLOW_TUN_PSP:
    case DOCA_FLOW_TUN_IP_IN_IP:
        break;
    case DOCA_FLOW_TUN_VXLAN:
        extend_field_to_changeable(vxlan_tun_id);
        verify_specific_field(vxlan_type);
        if (value->vxlan_type == DOCA_FLOW_TUN_EXT_VXLAN_GBP) {
            extend_field_to_changeable(vxlan_gbp_group_policy_id);
        }

        break;
    case DOCA_FLOW_TUN_GRE:
        verify_specific_field(key_present);
        if (value->key_present) {
            extend_field_to_changeable(gre_key);
        }

        extend_field_to_changeable(protocol);
        break;
    case DOCA_FLOW_TUN_GENEVE:
        extend_field_to_changeable(geneve.vni);
        extend_field_to_changeable(geneve.next_proto);
        extend_field_to_changeable(geneve.o_c);
        verify_specific_field(geneve.ver_opt_len);

        for (int opt_idx = 0;
             opt_idx < DOCA_FLOW_GENEVE_OPT_LEN_MAX;
             opt_idx++) {
            opt = &value->geneve_options[opt_idx];
            uint8_t len = opt->length;
            uint8_t i;

            if (!len || !opt->type) {
                break;
            }

            verify_specific_field(geneve_options[opt_idx].length);
            verify_specific_field(geneve_options[opt_idx].type);
            verify_specific_field_class_id(geneve_options[opt_idx].class_id);

            for (i = 0; i < len; i++) {
                opt_idx++;
                if (opt_idx >= DOCA_FLOW_GENEVE_OPT_LEN_MAX) {
                    break;
                }

                extend_field_to_changeable(geneve_options[opt_idx].data);
            }
        }

        break;
    }
}

static void
mask_to_changeable_value_parser_meta(struct ds *ds, char *prefix,
                                     struct doca_flow_parser_meta *value,
                                     struct doca_flow_parser_meta *mask,
                                     struct doca_flow_parser_meta *used)
{
    extend_field_to_changeable(port_id);
    extend_field_to_changeable(meter_color);
    extend_field_to_changeable(random);
    extend_field_to_changeable(outer_ip_fragmented);
    extend_field_to_changeable(inner_ip_fragmented);
    verify_specific_field(outer_l2_type);
    verify_specific_field(inner_l2_type);
    verify_specific_field(outer_l3_type);
    verify_specific_field(inner_l3_type);
    verify_specific_field(outer_l4_type);
    verify_specific_field(inner_l4_type);
}

static void
mask_to_changeable_value_meta(struct ds *ds, char *prefix,
                              struct doca_flow_meta *value,
                              struct doca_flow_meta *mask,
                              struct doca_flow_meta *used)
{
    for (int i = 0; i < DOCA_FLOW_META_SCRATCH_PAD_MAX; i++) {
        extend_field_to_changeable(u32[i]);
    }

    extend_field_to_changeable(pkt_meta);
}

static void
mask_to_changeable_value_mark(struct ds *ds, char *prefix,
                              struct ovs_doca_flow_actions *value,
                              struct ovs_doca_flow_actions *mask,
                              struct ovs_doca_flow_actions *used)
{
    extend_field_to_changeable(mark);
}

static void
action_mask_to_changeable_value(struct ovs_doca_flow_actions *ovalue,
                                struct ovs_doca_flow_actions *omask,
                                struct ds *ds)
{
    struct doca_flow_actions *value = &ovalue->d, *mask = &omask->d;
    struct ovs_doca_flow_actions u;
    struct doca_flow_actions *used;
    char *prefix = "actions";

    memcpy(&u, omask, sizeof u);
    used = &u.d;

    verify_specific_field(pop_vlan);

    mask_to_changeable_value_meta(ds, "actions.meta",
                                  &value->meta, &mask->meta, &used->meta);
    mask_to_changeable_value_mark(ds, "actions.mark", ovalue, omask, &u);
    mask_to_changeable_value_parser_meta(ds, "actions.parser_meta",
                                         &value->parser_meta,
                                         &mask->parser_meta,
                                         &used->parser_meta);
    mask_to_changeable_value_header_format(ds, "actions.outer",
                                           &value->outer, &mask->outer,
                                           &used->outer, DOCA_FLOW_TUN_NONE);
    mask_to_changeable_value_tun(ds, "actions.tun",
                                 &value->tun, &mask->tun, &used->tun);

    verify_specific_field(encap_type);
    if (value->encap_type) {
        if (value->encap_type == DOCA_FLOW_RESOURCE_TYPE_SHARED) {
            extend_field_to_changeable(shared_encap_id);
            value->shared_encap_id = mask->shared_encap_id;
        } else {
            verify_specific_field(encap_cfg.is_l2);
            mask_to_changeable_value_header_format(
                    ds, "actions.encap.outer",
                    &value->encap_cfg.encap.outer,
                    &mask->encap_cfg.encap.outer,
                    &used->encap_cfg.encap.outer,
                    value->encap_cfg.encap.tun.type);
            mask_to_changeable_value_tun(ds, "actions.encap.tun",
                                         &value->encap_cfg.encap.tun,
                                         &mask->encap_cfg.encap.tun,
                                         &used->encap_cfg.encap.tun);
        }
    }

    verify_specific_field(decap_type);
    verify_specific_field(decap_cfg.is_l2);

    verify_specific_field(has_push);
    if (value->has_push) {
        verify_specific_field(push.type);
        if (value->push.type == DOCA_FLOW_PUSH_ACTION_VLAN) {
            extend_field_to_changeable(push.vlan.vlan_hdr.tci);
            extend_field_to_changeable(push.vlan.eth_type);
        }
    }

    ovs_assert(is_all_zeros(used, sizeof *used));
}

static void
match_mask_to_changeable_value(struct ovs_doca_flow_match *ovalue,
                               struct ovs_doca_flow_match *omask,
                               struct ds *ds)
{
    struct doca_flow_match *value = &ovalue->d, *mask = &omask->d;
    struct ovs_doca_flow_match u;
    struct doca_flow_match *used;

    memcpy(&u, omask, sizeof u);
    used = &u.d;

    mask_to_changeable_value_meta(ds, "match.meta",
                                  &value->meta, &mask->meta, &used->meta);
    mask_to_changeable_value_parser_meta(ds, "match.parser_meta",
                                         &value->parser_meta,
                                         &mask->parser_meta,
                                         &used->parser_meta);
    mask_to_changeable_value_tun(ds, "match.tun",
                                 &value->tun, &mask->tun, &used->tun);
    mask_to_changeable_value_header_format(ds, "match.inner",
                                           &value->inner, &mask->inner,
                                           &used->inner, DOCA_FLOW_TUN_NONE);
    mask_to_changeable_value_header_format(ds, "match.outer",
                                           &value->outer, &mask->outer,
                                           &used->outer, DOCA_FLOW_TUN_NONE);

    ovs_assert(is_all_zeros(&u, sizeof u));
}

static void
fwd_to_changeable_value(struct doca_flow_fwd *value,
                        const struct doca_flow_fwd *fwd)
{
    /* Try and make forward value changeable per entry. */
    switch (fwd->type) {
    case DOCA_FLOW_FWD_PIPE:
        value->type = fwd->type;
        value->next_pipe = 0;
        break;
    case DOCA_FLOW_FWD_PORT:
        memset(value, 0xFF, sizeof(*value));
        value->type = fwd->type;
        break;
    case DOCA_FLOW_FWD_NONE:
    case DOCA_FLOW_FWD_DROP:
    case DOCA_FLOW_FWD_RSS:
    case DOCA_FLOW_FWD_TARGET:
    case DOCA_FLOW_FWD_CHANGEABLE:
    case DOCA_FLOW_FWD_ORDERED_LIST_PIPE:
    case DOCA_FLOW_FWD_TRIM:
        /* Use specific action */
        *value = *fwd;
        break;
    case DOCA_FLOW_FWD_HASH_PIPE:
        OVS_NOT_REACHED();
        break;
    }
}

static int
doca_pipe_group_mask_ctx_init(void *ctx_, void *arg_)
{
    struct doca_pipe_group_mask_ctx *mask_ctx = ctx_, *next, *prev;
    struct doca_pipe_group_mask_arg *arg = arg_;
    struct doca_flow_pipe *prev_pipe;
    struct doca_flow_fwd miss_fwd;
    struct netdev *netdev;
    int ret;

    netdev = arg->key->group_ctx->esw_netdev;

    mask_ctx->priority = arg->key->priority;
    mask_ctx->group_ctx = arg->key->group_ctx;
    mask_ctx->name = xasprintf("%s-p%d", mask_ctx->group_ctx->name,
                               mask_ctx->priority);
    VLOG_DBG_RL(&rl, "%s: %p: group_ctx=%p, %s", __FUNCTION__, mask_ctx,
                mask_ctx->group_ctx, mask_ctx->name);

    prev = NULL;
    ovs_mutex_lock(&mask_ctx->group_ctx->lock);
    LIST_FOR_EACH (next, list, &mask_ctx->group_ctx->list) {
        if (mask_ctx->priority < next->priority) {
            break;
        }

        prev = next;
        continue;
    }

    ovs_mutex_unlock(&mask_ctx->group_ctx->lock);

    prev_pipe = prev ? prev->pipe : mask_ctx->group_ctx->start_anchor;

    mask_ctx->pipe_size = get_pipe_size(mask_ctx->group_ctx);
    memset(&miss_fwd, 0, sizeof miss_fwd);
    miss_fwd.type = DOCA_FLOW_FWD_PIPE;
    miss_fwd.next_pipe = next ? next->pipe : mask_ctx->group_ctx->end_anchor;

    ret = ovs_doca_pipe_create(netdev, &arg->key->match_value,
                               &arg->key->match_value, &arg->key->monitor,
                               &arg->key->actions_value,
                               &arg->key->actions_mask, &arg->key->desc,
                               &arg->key->fwd, &miss_fwd, mask_ctx->pipe_size,
                               false, false, arg->allowed_queues_bitmap,
                               mask_ctx->name, &mask_ctx->pipe);
    if (ret) {
        if (ret == DOCA_ERROR_TOO_BIG) {
            VLOG_DBG_RL(&rl, "%s: Failed to create group mask prio %d "
                        "main pipe: Match too big",
                        netdev_get_name(netdev), mask_ctx->priority);
        } else {
            VLOG_ERR("%s: Failed to create group mask prio %d main pipe: %d "
                     "(%s)", netdev_get_name(netdev), mask_ctx->priority,
                     ret, doca_error_get_descr(ret));
        }

        goto err_pipe_create_main;
    }

    VLOG_DBG_RL(&rl, "%s: mask_ctx=%p, pipe=%p ->%p", mask_ctx->name,
                mask_ctx, mask_ctx->pipe, miss_fwd.next_pipe);

    memset(&miss_fwd, 0, sizeof miss_fwd);
    miss_fwd.type = DOCA_FLOW_FWD_PIPE;
    miss_fwd.next_pipe = mask_ctx->pipe;

    ret = doca_flow_pipe_update_miss(prev_pipe, &miss_fwd);
    VLOG_DBG_RL(&rl, "miss update: mask_ctx=%p, pipe=%p ->%p", prev, prev_pipe,
                miss_fwd.next_pipe);
    if (ret) {
        VLOG_ERR("%s: Failed to update group mask miss: %d (%s)",
                 netdev_get_name(netdev), ret, doca_error_get_descr(ret));
        goto err_miss_update_prev;
    }

    ovs_list_insert(next ? &next->list : &mask_ctx->group_ctx->list,
                    &mask_ctx->list);

    mask_ctx->match_str = ds_steal_cstr(&arg->match_ds);
    mask_ctx->actions_str = ds_steal_cstr(&arg->actions_ds);

    return 0;

err_miss_update_prev:
    doca_flow_pipe_destroy(mask_ctx->pipe);
err_pipe_create_main:
    free(mask_ctx->name);
    return ret;
}

static void
doca_pipe_group_mask_ctx_uninit(void *ctx_)
{
    struct doca_pipe_group_mask_ctx *mask_ctx = ctx_, *prev, *next;
    struct doca_flow_pipe *prev_pipe;
    struct doca_flow_fwd miss_fwd;
    int ret;

    VLOG_DBG_RL(&rl, "%s: %p: group_ctx=%p, %s", __FUNCTION__, mask_ctx,
                mask_ctx->group_ctx, mask_ctx->name);

    ovs_mutex_lock(&mask_ctx->group_ctx->lock);
    next = mask_ctx->list.next == &mask_ctx->group_ctx->list
       ? NULL
       : CONTAINER_OF(mask_ctx->list.next,
                      struct doca_pipe_group_mask_ctx, list);
    prev = mask_ctx->list.prev == &mask_ctx->group_ctx->list
       ? NULL
       : CONTAINER_OF(mask_ctx->list.prev,
                      struct doca_pipe_group_mask_ctx, list);
    prev_pipe = prev ? prev->pipe : mask_ctx->group_ctx->start_anchor;
    ovs_list_remove(&mask_ctx->list);
    ovs_mutex_unlock(&mask_ctx->group_ctx->lock);

    memset(&miss_fwd, 0, sizeof miss_fwd);
    miss_fwd.type = DOCA_FLOW_FWD_PIPE;
    miss_fwd.next_pipe = next ? next->pipe : mask_ctx->group_ctx->end_anchor;

    ret = doca_flow_pipe_update_miss(prev_pipe, &miss_fwd);
    VLOG_DBG_RL(&rl, "miss update: mask_ctx=%p, pipe=%p, ->%p", prev,
                prev_pipe, miss_fwd.next_pipe);
    ovs_assert(!ret);

    doca_flow_pipe_destroy(mask_ctx->pipe);

    free(mask_ctx->match_str);
    free(mask_ctx->actions_str);
    free(mask_ctx->name);
}

static const char *
doca_pipe_fwd_type_str(enum doca_flow_fwd_type type)
{
    switch (type) {
    case DOCA_FLOW_FWD_NONE:
        return "none";
    case DOCA_FLOW_FWD_RSS:
        return "rss";
    case DOCA_FLOW_FWD_PORT:
        return "port";
    case DOCA_FLOW_FWD_PIPE:
        return "pipe";
    case DOCA_FLOW_FWD_DROP:
        return "drop";
    case DOCA_FLOW_FWD_TARGET:
        return "target";
    case DOCA_FLOW_FWD_ORDERED_LIST_PIPE:
        return "ordered_list_pipe";
    case DOCA_FLOW_FWD_CHANGEABLE:
        return "changeable";
    case DOCA_FLOW_FWD_HASH_PIPE:
        return "fwd_hash_pipe";
    case DOCA_FLOW_FWD_TRIM:
        return "trim";
    }

    return "ERR";
}

static struct ds *
doca_pipe_group_mask_ctx_dump(struct ds *s, void *key_, void *ctx)
{
    struct doca_pipe_group_mask_ctx *mask_ctx = ctx;
    struct doca_pipe_group_mask_key *key = key_;
    struct doca_offload_esw_data *offload_data;
    struct refmap *group_mask_rfm;

    if (!mask_ctx) {
        ds_put_cstr(s, "mask_ctx creation failed");
        return s;
    }

    offload_data =
        netdev_doca_get_esw_offload_data(mask_ctx->group_ctx->esw_netdev);
    group_mask_rfm = offload_data->group_mask_rfm;
    ds_put_format(s, "%s: fwd.type=%s, nr_entries=%u/%u, ", mask_ctx->name,
                  doca_pipe_fwd_type_str(key->fwd.type),
                  refmap_value_refcount_read(group_mask_rfm, mask_ctx),
                  mask_ctx->pipe_size);
    ds_put_format(s, "%s, %s", mask_ctx->match_str, mask_ctx->actions_str);

    return s;
}

static struct doca_pipe_group_mask_ctx *
doca_pipe_group_mask_ctx_ref(struct netdev *netdev,
                             struct doca_pipe_group_ctx *group_ctx,
                             const struct ovs_doca_flow_match *match,
                             struct ovs_doca_flow_match *match_mask,
                             struct ovs_doca_flow_actions *actions,
                             struct ovs_doca_flow_actions *actions_mask,
                             const struct doca_flow_action_desc *desc,
                             const struct doca_flow_monitor *monitor,
                             const struct doca_flow_fwd *fwd,
                             uint32_t priority, bool *too_big OVS_UNUSED,
                             uint64_t allowed_queues_bitmap)
{
    struct doca_offload_esw_data *offload_data =
        netdev_doca_get_esw_offload_data(netdev);
    struct doca_pipe_group_mask_ctx *mask_ctx;
    struct doca_pipe_group_mask_key key = {
        .group_ctx = group_ctx,
        .priority = priority,
        .encap_type = actions ? actions->encap_type : 0,
        .encap_size = actions ? actions->encap_size : 0,
    };
    struct doca_pipe_group_mask_arg arg = {
        .netdev = netdev,
        .key = &key,
        .match_ds = DS_EMPTY_INITIALIZER,
        .actions_ds = DS_EMPTY_INITIALIZER,
        .allowed_queues_bitmap = allowed_queues_bitmap,
    };

    /* Make fields which don't support changeable to specific. */
    if (actions_mask && actions->d.tun.type == DOCA_FLOW_TUN_GRE) {
        actions_mask->d.tun.key_present = actions->d.tun.key_present;
    }

    if (match && match_mask) {
        memcpy(&key.match_value, match, sizeof *match);
        memcpy(&key.match_mask, match_mask, sizeof *match_mask);
        match_mask_to_changeable_value(&key.match_value, &key.match_mask,
                                       &arg.match_ds);
    }

    if (is_all_zeros(&key.match_value, sizeof key.match_value)) {
        ds_put_format(&arg.match_ds, "empty_match");
    } else {
        ds_chomp(&arg.match_ds, ' ');
        ds_chomp(&arg.match_ds, ',');
    }

    if (actions_mask) {
        memcpy(&key.actions_value, actions, sizeof *actions);
        memcpy(&key.actions_mask, actions_mask, sizeof *actions_mask);
        action_mask_to_changeable_value(&key.actions_value, &key.actions_mask,
                                        &arg.actions_ds);
    }

    if (is_all_zeros(&key.actions_value, sizeof key.actions_value)) {
        ds_put_format(&arg.actions_ds, "empty_actions_mask");
    } else {
        ds_chomp(&arg.actions_ds, ' ');
        ds_chomp(&arg.actions_ds, ',');
    }

    fwd_to_changeable_value(&key.fwd, fwd);

    if (monitor) {
        memcpy(&key.monitor, monitor, sizeof *monitor);

        /* Change a shared counter/monitor to be specified per entry to
         * reuse such pipe. */
        if (monitor->meter_type == DOCA_FLOW_RESOURCE_TYPE_SHARED) {
            key.monitor.shared_meter.shared_meter_id = UINT32_MAX;
        }

        if (monitor->counter_type == DOCA_FLOW_RESOURCE_TYPE_SHARED) {
            key.monitor.shared_counter.shared_counter_id = UINT32_MAX;
        }
    }

    if (desc) {
        memcpy(&key.desc, desc, sizeof *desc);
    }

    mask_ctx = refmap_ref(offload_data->group_mask_rfm, &key, &arg);

    ds_destroy(&arg.match_ds);
    ds_destroy(&arg.actions_ds);
    return mask_ctx;
}

static void
doca_pipe_group_mask_ctx_unref(struct doca_pipe_group_mask_ctx *mask_ctx)
{
    struct doca_offload_esw_data *offload_data;

    if (!mask_ctx) {
        return;
    }

    offload_data =
        netdev_doca_get_esw_offload_data(mask_ctx->group_ctx->esw_netdev);
    refmap_unref(offload_data->group_mask_rfm, mask_ctx);
}

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
    OVS_EXCLUDED(mgmt_queue_lock)
{
    struct doca_pipe_group_ctx *group_ctx;
    doca_error_t ret = 0;

    memset(deh, 0, sizeof *deh);

    group_ctx = doca_pipe_group_ctx_ref(netdev, vport, group_type);
    if (!group_ctx) {
        return DOCA_ERROR_INVALID_VALUE;
    }

    deh->mctx =
        doca_pipe_group_mask_ctx_ref(netdev, group_ctx, match, match_mask,
                                     actions, actions_mask,
                                     action_descs ?
                                     action_descs->desc_array : NULL,
                                     monitor, fwd, priority, NULL,
                                     UINT64_C(1) << qid);
    if (!deh->mctx) {
        ret = DOCA_ERROR_INVALID_VALUE;
        goto err_mctx;
    }

    ret = ovs_doca_add_entry(netdev, qid, deh->mctx->pipe, match,
                             actions, monitor, fwd,
                             DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, &deh->entry);
    if (ret) {
        goto err_entry;
    }

    return 0;

err_entry:
    doca_pipe_group_mask_ctx_unref(deh->mctx);
    deh->mctx = NULL;
err_mctx:
    doca_pipe_group_ctx_unref(group_ctx);
    return ret;
}

doca_error_t
doca_pipe_group_del_deh(struct netdev *netdev,
                        uint16_t qid,
                        struct doca_entry_handle *deh)
{
    struct netdev_doca *dev = netdev_doca_cast(netdev);
    struct netdev_doca_esw_ctx *esw = dev->esw_ctx;
    doca_error_t ret;

    ret = ovs_doca_remove_entry(esw, qid,
                                DOCA_FLOW_ENTRY_FLAGS_NO_WAIT, &deh->entry);
    if (ret) {
        return ret;
    }

    doca_pipe_group_mask_ctx_unref(deh->mctx);
    if (deh->mctx) {
        doca_pipe_group_ctx_unref(deh->mctx->group_ctx);
    }

    deh->mctx = NULL;

    return 0;
}

static void
doca_pipe_group_ctx_dump_masks(struct doca_pipe_group_ctx *group_ctx,
                               struct doca_offload_esw_data *offload_data,
                               struct ds *out)
{
    struct doca_pipe_group_mask_ctx *mask_ctx;

    ovs_mutex_lock(&group_ctx->lock);
    LIST_FOR_EACH (mask_ctx, list, &group_ctx->list) {
        void *value;

        value = refmap_key_from_value(offload_data->group_mask_rfm, mask_ctx);
        doca_pipe_group_mask_ctx_dump(out, value, mask_ctx);
        ds_put_format(out, "\n");
    }

    ovs_mutex_unlock(&group_ctx->lock);
}

static void
doca_pipe_group_dump_netdev(struct netdev *netdev, struct ds *out)
{
    struct doca_offload_esw_data *offload_data =
        netdev_doca_get_esw_offload_data(netdev);
    void *key, *value;

    REFMAP_FOR_EACH (value, key, offload_data->group_rfm) {
        struct doca_pipe_group_ctx *group_ctx = value;
        struct doca_pipe_group_key *group_key = key;

        doca_pipe_group_ctx_dump(out, group_key, group_ctx);
        ds_put_format(out, "\n");
        doca_pipe_group_ctx_dump_masks(group_ctx, offload_data, out);
    }
}

static void
doca_pipe_group_dump(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds out = DS_EMPTY_INITIALIZER;
    struct dpif_port_dump dump;
    struct dpif_port dpif_port;
    struct netdev *netdev;
    struct dpif *dpif;
    int rv;

    rv = dpif_open("ovs-netdev", "netdev", &dpif);
    if (rv) {
        unixctl_command_reply_error(conn, "Cannot open netdev datapath");
        return;
    }

    DPIF_PORT_FOR_EACH (&dpif_port, &dump, dpif) {
        if (strcmp(dpif_port.type, "doca")) {
            continue;
        }

        rv = netdev_open(dpif_port.name, dpif_port.type, &netdev);
        if (rv) {
            continue;
        }

        if (netdev_doca_is_esw_mgr(netdev)) {
            doca_pipe_group_dump_netdev(netdev, &out);
        }

        netdev_close(netdev);
    }

    dpif_close(dpif);
    unixctl_command_reply(conn, ds_cstr(&out));
    ds_destroy(&out);
}

void
doca_pipe_group_init(struct netdev *netdev)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct doca_offload_esw_data *offload_data =
        netdev_doca_get_esw_offload_data(netdev);

    offload_data->group_rfm =
        refmap_create("doca-group", sizeof(struct doca_pipe_group_key),
                      sizeof(struct doca_pipe_group_ctx),
                      doca_pipe_group_ctx_init,
                      doca_pipe_group_ctx_uninit,
                      doca_pipe_group_ctx_dump);
    offload_data->group_mask_rfm =
        refmap_create("doca-group-pipe-mask",
                      sizeof(struct doca_pipe_group_mask_key),
                      sizeof(struct doca_pipe_group_mask_ctx),
                      doca_pipe_group_mask_ctx_init,
                      doca_pipe_group_mask_ctx_uninit,
                      doca_pipe_group_mask_ctx_dump);
    if (ovsthread_once_start(&once)) {
        unixctl_command_register("doca/pipe-group-dump", "", 0, 0,
                                 doca_pipe_group_dump, NULL);
        ovsthread_once_done(&once);
    }
}

void
doca_pipe_group_uninit(struct netdev *netdev)
{
    struct doca_offload_esw_data *offload_data =
        netdev_doca_get_esw_offload_data(netdev);

    refmap_destroy(offload_data->group_mask_rfm);
    refmap_destroy(offload_data->group_rfm);

    offload_data->group_mask_rfm = NULL;
    offload_data->group_rfm = NULL;
}
