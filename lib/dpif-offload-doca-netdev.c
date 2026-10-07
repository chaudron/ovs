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

#include <sys/types.h>
#include <netinet/in.h>

#include <doca_flow.h>

#include "cmap.h"
#include "doca-pipe-group.h"
#include "dpif-netdev.h"
#include "dpif-offload.h"
#include "dpif-offload-doca-private.h"
#include "netdev-provider.h"
#include "odp-util.h"
#include "ovs-doca.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "uuid.h"

#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_doca_netdev);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions are fulfilled by
 * read-locking the datapath 'port_rwlock' in lib/dpif-netdev.c. */

/* A mapping from pmd_id to flow_reference. */
struct pmd_id_to_flow_ref_data {
    struct cmap_node node;
    void *flow_reference;
    unsigned pmd_id;
};

struct pmd_data {
    struct cmap pmd_id_to_flow_ref;
    struct ovs_mutex map_lock;
};

struct doca_offload_handle {
    struct doca_entry_handle e;
};

/* A mapping from ufid to doca offload handle. */
struct ufid_to_doh_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct doca_offload_handle doh;
    OVSRCU_TYPE(struct pmd_data *) pmd_mapping;
    struct dpif_flow_stats stats;
    struct dpif_flow_stats baseline_stats;
    struct netdev *physdev;
    struct ovs_mutex lock;
    unsigned int creation_tid;
    bool dead;
};

struct doca_offload_netdev_data {
    struct cmap ufid_to_doh;
    uint64_t *doh_counters;
    struct ovs_mutex map_lock;
};

struct doca_match_headers {
    struct doca_flow_header_format *hdr_spec, *hdr_mask;
    enum doca_flow_l2_meta *l2_spec, *l2_mask;
    enum doca_flow_l3_meta *l3_spec, *l3_mask;
    enum doca_flow_l4_meta *l4_spec, *l4_mask;
    uint8_t *frag_mask;
};

struct doca_vars {
    struct doca_offload *offload;
    struct netdev *netdev;

    struct ovs_doca_flow_match *dmatch;
    struct ovs_doca_flow_match *dmatch_masks;
    struct doca_flow_fwd *fwd;
    struct doca_flow_monitor *monitor;

    odp_port_t vport;
    enum doca_pipe_group_type group_type;
    uint32_t priority;
};

static struct pmd_data *
pmd_data_init(void)
{
    struct pmd_data *mapping = xmalloc(sizeof *mapping);

    ovs_mutex_init(&mapping->map_lock);
    cmap_init(&mapping->pmd_id_to_flow_ref);
    return mapping;
}

static void
pmd_data_associate(struct pmd_data *mapping, unsigned pmd_id,
                   void *flow_reference)
{
    struct pmd_id_to_flow_ref_data *pmd_data = xmalloc(sizeof *pmd_data);

    pmd_data->flow_reference = flow_reference;
    pmd_data->pmd_id = pmd_id;

    ovs_mutex_lock(&mapping->map_lock);
    cmap_insert(&mapping->pmd_id_to_flow_ref, &pmd_data->node,
                hash_int(pmd_id, 0));
    ovs_mutex_unlock(&mapping->map_lock);
}

static void
pmd_data_disassociate(struct pmd_data *mapping, unsigned pmd_id)
{
    struct pmd_id_to_flow_ref_data *data;
    size_t hash = hash_int(pmd_id, 0);

    ovs_mutex_lock(&mapping->map_lock);

    CMAP_FOR_EACH_WITH_HASH_PROTECTED (data, node, hash,
                                       &mapping->pmd_id_to_flow_ref) {
        if (data->pmd_id == pmd_id) {
            cmap_remove(&mapping->pmd_id_to_flow_ref, &data->node, hash);
            ovsrcu_postpone(free, data);
            break;
        }
    }

    ovs_mutex_unlock(&mapping->map_lock);
}

static struct pmd_id_to_flow_ref_data*
pmd_data_get(const struct ufid_to_doh_data *doh_data, unsigned pmd_id)
{
    struct pmd_id_to_flow_ref_data *data;
    size_t hash = hash_int(pmd_id, 0);
    struct pmd_data *mapping;

    mapping = ovsrcu_get(struct pmd_data *, &doh_data->pmd_mapping);
    if (!mapping) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &mapping->pmd_id_to_flow_ref) {
        if (data->pmd_id == pmd_id) {
            return data;
        }
    }

    return NULL;
}

static bool
pmd_data_update(const struct ufid_to_doh_data *doh_data, unsigned pmd_id,
                void *new_flow_reference, void **previous_flow_reference)
{
    struct pmd_id_to_flow_ref_data *data;

    data = pmd_data_get(doh_data, pmd_id);
    if (!data) {
        return false;
    }

    *previous_flow_reference = data->flow_reference;
    data->flow_reference = new_flow_reference;
    return true;
}

static bool
pmd_data_find_and_delete(const struct ufid_to_doh_data *doh_data,
                         unsigned pmd_id, void *flow_reference)
{
    struct pmd_data *mapping = ovsrcu_get(struct pmd_data *,
                                          &doh_data->pmd_mapping);
    struct pmd_id_to_flow_ref_data *data;
    size_t hash = hash_int(pmd_id, 0);

    ovs_assert(mapping);
    ovs_mutex_lock(&mapping->map_lock);

    CMAP_FOR_EACH_WITH_HASH_PROTECTED (data, node, hash,
                                       &mapping->pmd_id_to_flow_ref) {
        if (data->pmd_id == pmd_id && data->flow_reference == flow_reference) {
            cmap_remove(&mapping->pmd_id_to_flow_ref, &data->node, hash);
            ovsrcu_postpone(free, data);

            ovs_mutex_unlock(&mapping->map_lock);
            return true;
        }
    }

    ovs_mutex_unlock(&mapping->map_lock);
    return false;
}

static void
pmd_data_cleanup(struct doca_offload *offload, struct pmd_data *mapping)
{
    struct pmd_id_to_flow_ref_data *data;

    if (!mapping) {
        return;
    }

    ovs_mutex_lock(&mapping->map_lock);

    CMAP_FOR_EACH (data, node, &mapping->pmd_id_to_flow_ref) {
        cmap_remove(&mapping->pmd_id_to_flow_ref, &data->node,
                    hash_int(data->pmd_id, 0));

        doca_offload_unreference(offload, data->pmd_id, data->flow_reference);
        ovsrcu_postpone(free, data);
    }

    ovs_mutex_unlock(&mapping->map_lock);
}

static void
pmd_data_destroy(struct pmd_data *mapping)
{
    if (mapping) {
        ovs_mutex_destroy(&mapping->map_lock);
        cmap_destroy(&mapping->pmd_id_to_flow_ref);
        free(mapping);
    }
}

static int
offload_data_init(struct netdev *netdev, unsigned int offload_thread_count)
{
    struct doca_offload_netdev_data *data;

    data = xzalloc(sizeof *data);
    ovs_mutex_init(&data->map_lock);
    cmap_init(&data->ufid_to_doh);
    data->doh_counters = xcalloc(1 + offload_thread_count,
                                 sizeof *data->doh_counters);

    ovsrcu_set(&netdev->hw_info.offload_data, (void *) data);
    atomic_store_relaxed(&netdev->hw_info.post_process_api_supported, true);

    return 0;
}

static void
offload_data_destroy__(struct doca_offload_netdev_data *data)
{
    ovs_mutex_destroy(&data->map_lock);
    free(data->doh_counters);
    free(data);
}

static void
offload_data_destroy(struct netdev *netdev)
{
    struct doca_offload_netdev_data *data;
    struct ufid_to_doh_data *node;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (!data) {
        return;
    }

    if (!cmap_is_empty(&data->ufid_to_doh)) {
        VLOG_ERR("Incomplete flush: %s contains doh elements",
                 netdev_get_name(netdev));
    }

    CMAP_FOR_EACH (node, node, &data->ufid_to_doh) {
        ovsrcu_postpone(free, node);
    }

    cmap_destroy(&data->ufid_to_doh);
    ovsrcu_postpone(offload_data_destroy__, data);

    ovsrcu_set(&netdev->hw_info.offload_data, NULL);
}

static void
offload_data_lock(struct netdev *netdev)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct doca_offload_netdev_data *data;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (!data) {
        return;
    }

    ovs_mutex_lock(&data->map_lock);
}

static void
offload_data_unlock(struct netdev *netdev)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct doca_offload_netdev_data *data;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (!data) {
        return;
    }

    ovs_mutex_unlock(&data->map_lock);
}

static struct cmap *
offload_data_map(struct netdev *netdev)
{
    struct doca_offload_netdev_data *data;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);

    return data ? &data->ufid_to_doh : NULL;
}

static bool
offload_data_maps(struct netdev *netdev, struct cmap **ufid_map)
{
    struct doca_offload_netdev_data *data;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);

    if (!data) {
        return false;
    }

    *ufid_map = &data->ufid_to_doh;
    return true;
}

/* Find doh_data with @ufid. */
static struct ufid_to_doh_data *
ufid_to_doh_data_find(struct netdev *netdev, const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_doh_data *data;
    struct cmap *map = offload_data_map(netdev);

    if (!map) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static struct ufid_to_doh_data *
ufid_to_doh_data_find_pmd_and_update(struct netdev *netdev,
                                          const ovs_u128 *ufid,
                                          unsigned pmd_id, bool *found_pmd,
                                          void *new_flow_reference,
                                          void **previous_flow_reference)
{
    struct ufid_to_doh_data *data = ufid_to_doh_data_find(netdev,
                                                                    ufid);
    if (data) {
        *found_pmd = pmd_data_update(data, pmd_id, new_flow_reference,
                                     previous_flow_reference);
    } else {
        *found_pmd = false;
    }

    return data;
}

static void
ufid_to_doh_set(struct ufid_to_doh_data *data,
                struct netdev *physdev,
                struct pmd_data *pmd_mapping)
{
    if (data->physdev) {
        ovs_assert(data->physdev == physdev);
    } else {
        data->physdev = netdev_ref(physdev);
    }

    ovsrcu_set(&data->pmd_mapping, pmd_mapping);
}

static int
ufid_to_doh_associate(struct ufid_to_doh_data *data,
                      const ovs_u128 *ufid,
                      struct netdev *physdev,
                      struct pmd_data *pmd_mapping)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct cmap *map;

    if (!offload_data_maps(physdev, &map)) {
        return ENODEV;
    }

    /* We already checked before that no one inserted a
     * doh for this ufid.  As the ufid dispatch is per
     * thread id, this ufid would have been serviced by
     * this thread and sync is implicit. */

    data->ufid = *ufid;
    data->creation_tid = doca_offload_thread_id();
    ovs_mutex_init(&data->lock);
    ufid_to_doh_set(data, physdev, pmd_mapping);

    offload_data_lock(physdev);
    cmap_insert(map, CONST_CAST(struct cmap_node *, &data->node), hash);
    offload_data_unlock(physdev);

    return 0;
}

static void
doh_data_unref(struct ufid_to_doh_data *data)
{
    struct pmd_data *pmd_mapping = ovsrcu_get(struct pmd_data *,
                                              &data->pmd_mapping);

    pmd_data_destroy(pmd_mapping);
    ovs_mutex_destroy(&data->lock);
    free(data);
}

static void
ufid_to_doh_disassociate(struct ufid_to_doh_data *data)
    OVS_REQUIRES(data->lock)
{
    size_t hash = hash_bytes(&data->ufid, sizeof data->ufid, 0);
    struct pmd_data *pmd_mapping;
    struct cmap *map;

    if (!offload_data_maps(data->physdev, &map)) {
        return;
    }

    offload_data_lock(data->physdev);
    cmap_remove(map, CONST_CAST(struct cmap_node *, &data->node), hash);
    offload_data_unlock(data->physdev);

    netdev_close(data->physdev);

    /* There should be no more users before removing the hw flow. */
    pmd_mapping = ovsrcu_get(struct pmd_data *, &data->pmd_mapping);
    ovs_assert(!pmd_mapping || !cmap_count(&pmd_mapping->pmd_id_to_flow_ref));

    ovsrcu_postpone(doh_data_unref, data);
}

static int
doh_data_destroy(struct doca_offload *offload,
                 struct ufid_to_doh_data *doh_data,
                 bool force_destroy,
                 bool modification)
{
    unsigned int tid = doca_offload_thread_id();
    struct doca_offload_netdev_data *data;
    struct doca_offload_handle *doh;
    struct pmd_data *pmd_mapping;
    struct netdev *physdev;
    int ret;

    if (!modification) {
        ovs_mutex_lock(&doh_data->lock);
    }

    pmd_mapping = ovsrcu_get(struct pmd_data *, &doh_data->pmd_mapping);

    /* Only delete the flow from HW if no PMDs are using it, and it's not a
     * forceful destroy. */
    if (doh_data->dead
        || (!force_destroy && pmd_mapping
            && cmap_count(&pmd_mapping->pmd_id_to_flow_ref))) {
        if (!modification) {
            ovs_mutex_unlock(&doh_data->lock);
        }

        return 0;
    }

    if (force_destroy) {
        pmd_data_cleanup(offload, pmd_mapping);
    }

    doh_data->dead = true;

    doh = &doh_data->doh;
    physdev = doh_data->physdev;

    ret = doca_pipe_group_del_deh(physdev, tid, &doh->e);
    if (ret) {
        goto out;
    }

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &physdev->hw_info.offload_data);
    data->doh_counters[tid]--;

    if (!modification) {
        ufid_to_doh_disassociate(doh_data);
    }

out:
    if (!modification) {
        ovs_mutex_unlock(&doh_data->lock);
    }

    return ret;
}

static int
deh_add(struct doca_vars *vars,
        struct doca_entry_handle *deh)
{
    unsigned int tid = doca_offload_thread_id();
    struct doca_offload_netdev_data *data;
    doca_error_t rv;

    rv = doca_pipe_group_add_deh(vars->netdev, tid, vars->vport,
                                 vars->group_type, vars->priority,
                                 vars->dmatch, vars->dmatch_masks, NULL, NULL,
                                 NULL, vars->monitor, vars->fwd, deh);
    if (rv) {
        return rv;
    }

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &vars->netdev->hw_info.offload_data);
    data->doh_counters[tid]++;

    return 0;
}

static void
metadata_match_ignore(struct match *match)
{
    if (match->wc.masks.dp_hash &&
        (match->flow.dp_hash & match->wc.masks.dp_hash) == 0) {
        match->wc.masks.dp_hash = 0;
    }

    if (match->wc.masks.skb_priority &&
        (match->flow.skb_priority & match->wc.masks.skb_priority) == 0) {
        match->wc.masks.skb_priority = 0;
    }

    if (match->wc.masks.ct_state &&
        (match->flow.ct_state & match->wc.masks.ct_state) == 0) {
        match->wc.masks.ct_state = 0;
    }

    if (match->wc.masks.ct_zone &&
        (match->flow.ct_zone & match->wc.masks.ct_zone) == 0) {
        match->wc.masks.ct_zone = 0;
    }

    if (match->wc.masks.ct_mark &&
        (match->flow.ct_mark & match->wc.masks.ct_mark) == 0) {
        match->wc.masks.ct_mark = 0;
    }

    for (int i = 0; i < 3; i++) {
        if (match->wc.masks.ct_label.u32[i] &&
            (match->flow.ct_label.u32[i] &
             match->wc.masks.ct_label.u32[i]) == 0) {
            match->wc.masks.ct_label.u32[i] = 0;
        }
    }
}

static void
doca_match_headers_set(struct ovs_doca_flow_match *dmatch,
                       struct ovs_doca_flow_match *dmatch_masks,
                       bool inner,
                       struct doca_match_headers *dmh)
{
    memset(dmh, 0, sizeof *dmh);

    if (inner) {
        dmh->hdr_spec = &dmatch->d.inner;
        dmh->hdr_mask = &dmatch_masks->d.inner;
        dmh->l2_spec = &dmatch->d.parser_meta.inner_l2_type;
        dmh->l2_mask = &dmatch_masks->d.parser_meta.inner_l2_type;
        dmh->l3_spec = &dmatch->d.parser_meta.inner_l3_type;
        dmh->l3_mask = &dmatch_masks->d.parser_meta.inner_l3_type;
        dmh->l4_spec = &dmatch->d.parser_meta.inner_l4_type;
        dmh->l4_mask = &dmatch_masks->d.parser_meta.inner_l4_type;
        dmh->frag_mask = &dmatch_masks->d.parser_meta.inner_ip_fragmented;
    } else {
        dmh->hdr_spec = &dmatch->d.outer;
        dmh->hdr_mask = &dmatch_masks->d.outer;
        dmh->l2_spec = &dmatch->d.parser_meta.outer_l2_type;
        dmh->l2_mask = &dmatch_masks->d.parser_meta.outer_l2_type;
        dmh->l3_spec = &dmatch->d.parser_meta.outer_l3_type;
        dmh->l3_mask = &dmatch_masks->d.parser_meta.outer_l3_type;
        dmh->l4_spec = &dmatch->d.parser_meta.outer_l4_type;
        dmh->l4_mask = &dmatch_masks->d.parser_meta.outer_l4_type;
        dmh->frag_mask = &dmatch_masks->d.parser_meta.outer_ip_fragmented;
    }
}

static int
parse_flow_match(struct doca_vars *vars,
                 struct match *match,
                 struct doca_match_headers *dmh,
                 const ovs_u128 *ufid)
{
#define copy_match_field(dfield, mfield)                               \
    ({                                                                 \
        const uint8_t *_mspec = (const uint8_t *) &match->flow.mfield; \
        uint8_t *_dmatch = (uint8_t *) &dmh->hdr_spec->dfield;         \
        uint8_t *_mmask = (uint8_t *) &match->wc.masks.mfield;         \
        size_t _size = sizeof dmh->hdr_spec->dfield;                   \
        bool _field_on = false;                                        \
                                                                       \
        memcpy(&dmh->hdr_mask->dfield, _mmask, _size);                 \
        for (int _i = 0; _i < _size; _i++) {                           \
            _dmatch[_i] = _mspec[_i] & _mmask[_i];                     \
            _field_on |= !!_mmask[_i];                                 \
            _mmask[_i] = 0;                                            \
        }                                                              \
                                                                       \
        _field_on;                                                     \
    })

    match->wc.masks.in_port.odp_port = 0;
    vars->vport = ODPP_NONE;

    /* recirc id must be zero. */
    if (match->wc.masks.recirc_id & match->flow.recirc_id) {
        return EOPNOTSUPP;
    }

    vars->group_type = DOCA_PIPE_GROUP_TYPE_NONE;
    match->wc.masks.recirc_id = 0;
    match->wc.masks.packet_type = 0;

    vars->dmatch->d.parser_meta.port_id =
        netdev_doca_get_port_id(vars->netdev);
    memset(&vars->dmatch_masks->d.parser_meta.port_id, 0xFF,
           sizeof vars->dmatch_masks->d.parser_meta.port_id);

    /* Eth. */
    copy_match_field(eth.src_mac, dl_src);
    copy_match_field(eth.dst_mac, dl_dst);
    copy_match_field(eth.type, dl_type);
    vars->priority = DOCA_OFFLOAD_PRIORITY_LOW;

    /* VLAN. */
    if (match->wc.masks.vlans[0].tci) {
        if (match->flow.vlans[0].tci) {
            *dmh->l2_spec = DOCA_FLOW_L2_META_SINGLE_VLAN;
            match->wc.masks.vlans[0].tci &= ~htons(VLAN_CFI);
            copy_match_field(eth_vlan[0].tci, vlans[0].tci);
            dmh->hdr_spec->l2_valid_headers = DOCA_FLOW_L2_VALID_HEADER_VLAN_0;
            dmh->hdr_mask->l2_valid_headers = DOCA_FLOW_L2_VALID_HEADER_VLAN_0;
        } else {
            *dmh->l2_spec = DOCA_FLOW_L2_META_NO_VLAN;
        }
    }

    *dmh->l2_mask = UINT32_MAX;
    memset(&match->wc.masks.vlans[0], 0, sizeof match->wc.masks.vlans[0]);

    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        /* IPv4. */
        if (copy_match_field(ip4.src_ip, nw_src) |
            copy_match_field(ip4.dst_ip, nw_dst) |
            copy_match_field(ip4.next_proto, nw_proto) |
            copy_match_field(ip4.ttl, nw_ttl) |
            copy_match_field(ip4.dscp_ecn, nw_tos)) {
            dmh->hdr_spec->l3_type = DOCA_FLOW_L3_TYPE_IP4;
            dmh->hdr_mask->l3_type = DOCA_FLOW_L3_TYPE_IP4;
        }

        *dmh->l3_spec = DOCA_FLOW_L3_META_IPV4;
        *dmh->l3_mask = DOCA_FLOW_L3_META_IPV4;

        /* DOCA API does not support differentiation between first/later
         * frags.  Reject both. */
        *dmh->frag_mask = UINT8_MAX;
        match->wc.masks.nw_frag = 0;
        vars->priority = DOCA_OFFLOAD_PRIORITY_HIGH;
    } else if (match->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        /* IPv6. */
        if (copy_match_field(ip6.src_ip, ipv6_src) |
            copy_match_field(ip6.dst_ip, ipv6_dst) |
            copy_match_field(ip6.next_proto, nw_proto) |
            copy_match_field(ip6.hop_limit, nw_ttl) |
            copy_match_field(ip6.traffic_class, nw_tos)) {
            dmh->hdr_spec->l3_type = DOCA_FLOW_L3_TYPE_IP6;
            dmh->hdr_mask->l3_type = DOCA_FLOW_L3_TYPE_IP6;
        }

        *dmh->l3_spec = DOCA_FLOW_L3_META_IPV6;
        *dmh->l3_mask = DOCA_FLOW_L3_META_IPV6;

        /* DOCA API does not support differentiation between first/later
         * frags.  Reject both. */
        *dmh->frag_mask = UINT8_MAX;
        match->wc.masks.nw_frag = 0;
        vars->priority = DOCA_OFFLOAD_PRIORITY_MED;
    }

    if (match->flow.nw_proto == IPPROTO_TCP) {
        if (copy_match_field(tcp.l4_port.src_port, tp_src) |
            copy_match_field(tcp.l4_port.dst_port, tp_dst) |
            copy_match_field(tcp.flags, tcp_flags)) {
            dmh->hdr_spec->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
            dmh->hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
        }

        *dmh->l4_spec = DOCA_FLOW_L4_META_TCP;
        *dmh->l4_mask = DOCA_FLOW_L4_META_TCP;
    } else if (match->flow.nw_proto == IPPROTO_UDP) {
        if (copy_match_field(udp.l4_port.src_port, tp_src) |
            copy_match_field(udp.l4_port.dst_port, tp_dst)) {
            dmh->hdr_spec->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
            dmh->hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
        }

        *dmh->l4_spec = DOCA_FLOW_L4_META_UDP;
        *dmh->l4_mask = DOCA_FLOW_L4_META_UDP;
    } else if (match->flow.nw_proto == IPPROTO_ICMP) {
        if (copy_match_field(icmp.type, tp_src) |
            copy_match_field(icmp.code, tp_dst)) {
            dmh->hdr_spec->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP;
            dmh->hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP;
        }

        *dmh->l4_spec = DOCA_FLOW_L4_META_ICMP;
        *dmh->l4_mask = DOCA_FLOW_L4_META_ICMP;
    } else if (match->flow.nw_proto == IPPROTO_ICMPV6) {
        if (copy_match_field(icmp.type, tp_src) |
            copy_match_field(icmp.code, tp_dst)) {
            dmh->hdr_spec->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP6;
            dmh->hdr_mask->l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_ICMP6;
        }

        *dmh->l4_spec = DOCA_FLOW_L4_META_ICMP;
        *dmh->l4_mask = DOCA_FLOW_L4_META_ICMP;
    }

    /* Ignore ==0 metadata matches on recirc 0. */
    if (match->flow.recirc_id == 0) {
        metadata_match_ignore(match);
    }

    if (!is_all_zeros(&match->wc.masks, sizeof match->wc.masks)) {
        struct ds s = DS_EMPTY_INITIALIZER;

        match_format(match, NULL, &s, OFP_DEFAULT_PRIORITY);
        VLOG_DBG_RL(&rl, "%s: matches of ufid "UUID_FMT" are not supported: "
                    "%s", netdev_get_name(vars->netdev),
                    UUID_ARGS((struct uuid *) ufid), ds_cstr(&s));
        ds_destroy(&s);
        return EOPNOTSUPP;
    }

    return 0;

#undef copy_match_field
}

static int
get_output_port_id(struct doca_vars *vars,
                   const struct nlattr *nla,
                   uint16_t *port_id)
{
    struct netdev *outdev;
    odp_port_t port;

    port = nl_attr_get_odp_port(nla);
    outdev = doca_offload_get_netdev(vars->offload, port);
    if (!outdev) {
        VLOG_DBG_RL(&rl, "Cannot find netdev for odp port %"PRIu32, port);
        return ENODEV;
    }

    if (!dpif_offload_netdev_same_offload(vars->netdev, outdev)) {
        VLOG_DBG_RL(&rl, "%s: Output to port \'%s\' cannot be offloaded",
                    netdev_get_name(vars->netdev), netdev_get_name(outdev));
        return EOPNOTSUPP;
    }

    *port_id = netdev_doca_get_port_id(outdev);
    if (*port_id == DPDK_ETH_PORT_ID_INVALID) {
        VLOG_DBG_RL(&rl, "%s: Can't get port_id for %s",
                    netdev_get_name(vars->netdev), netdev_get_name(outdev));
        return EOPNOTSUPP;
    }

    return 0;
}

static int
parse_flow_actions(struct doca_vars *vars,
                   struct nlattr *nl_actions,
                   size_t nl_actions_len)
{
    struct nlattr *nla;
    size_t left;

    NL_ATTR_FOR_EACH_UNSAFE (nla, left, nl_actions, nl_actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            int error;

            if (left > NLA_ALIGN(nla->nla_len)) {
                VLOG_DBG_RL(&rl, "Unsupported non-last output action");
                return EOPNOTSUPP;
            }

            vars->fwd->type = DOCA_FLOW_FWD_PORT;
            error = get_output_port_id(vars, nla, &vars->fwd->port_id);
            if (error) {
                return error;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_DROP) {
            if (left > NLA_ALIGN(nla->nla_len)) {
                VLOG_DBG_RL(&rl, "Unsupported non-last drop action");
                return EOPNOTSUPP;
            }

            vars->fwd->type = DOCA_FLOW_FWD_DROP;
        } else {
            VLOG_DBG_RL(&rl, "Unsupported action type %d", nl_attr_type(nla));
            return EOPNOTSUPP;
        }
    }

    if (nl_actions_len == 0) {
        VLOG_DBG_RL(&rl, "No actions provided");
        return EOPNOTSUPP;
    }

    vars->monitor->counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    return 0;
}

static struct ufid_to_doh_data *
doca_offload_add_flow(struct doca_offload *offload,
                      struct pmd_data *pmd_mapping, struct netdev *netdev,
                      struct match *match, struct nlattr *nl_actions,
                      size_t actions_len, const ovs_u128 *ufid,
                      struct ufid_to_doh_data *old_doh_data)
{
    struct ovs_doca_flow_match dmatch, dmatch_masks;
    struct ufid_to_doh_data *doh_data = NULL;
    struct doca_flow_monitor monitor;
    struct doca_offload_handle *doh;
    struct doca_match_headers dmh;
    struct doca_flow_fwd fwd;
    struct doca_vars vars = {
        .offload = offload,
        .netdev = netdev,
        .dmatch = &dmatch,
        .dmatch_masks = &dmatch_masks,
        .fwd = &fwd,
        .monitor = &monitor,
    };

    memset(&dmatch, 0, sizeof dmatch);
    memset(&dmatch_masks, 0, sizeof dmatch_masks);
    memset(&fwd, 0, sizeof fwd);
    memset(&monitor, 0, sizeof monitor);

    doh_data = old_doh_data ? old_doh_data : xzalloc(sizeof *doh_data);
    if (!doh_data) {
        return NULL;
    }

    memset(&doh_data->doh, 0, sizeof doh_data->doh);
    doh = &doh_data->doh;

    doca_match_headers_set(&dmatch, &dmatch_masks, false, &dmh);

    if (parse_flow_match(&vars, match, &dmh, ufid)) {
        VLOG_DBG_RL(&rl, "%s: matches of ufid "UUID_FMT" are not supported",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *) ufid));
        if (!old_doh_data) {
            free(doh_data);
        }

        return NULL;
    }

    if (parse_flow_actions(&vars, nl_actions, actions_len)) {
        VLOG_DBG_RL(&rl, "%s: actions of ufid "UUID_FMT" are not supported",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *) ufid));
        goto err_actions;
    }

    if (deh_add(&vars, &doh->e)) {
        goto err_deh_add;
    }

    if (old_doh_data) {
        ovs_mutex_lock(&doh_data->lock);
        ufid_to_doh_set(doh_data, netdev, pmd_mapping);
        doh_data->dead = false;
        ovs_mutex_unlock(&doh_data->lock);
    } else if (ufid_to_doh_associate(doh_data, ufid, netdev, pmd_mapping)) {
        goto err_associate;
    }

    VLOG_DBG("%s: installed flow (%p/%p) by ufid "UUID_FMT,
             netdev_get_name(netdev), doh->e.mctx, doh->e.entry,
             UUID_ARGS((struct uuid *) ufid));
    return doh_data;

err_associate:
    doh_data_destroy(offload, doh_data, false, true);
    free(doh_data);
    return NULL;
err_deh_add:
err_actions:
    if (!old_doh_data) {
        free(doh_data);
    }

    return NULL;
}

struct get_netdev_odp_aux {
    struct netdev *netdev;
    odp_port_t odp_port;
};

int
doca_netdev_flow_put(struct doca_offload *offload, unsigned pmd_id,
                     void *flow_reference, struct netdev *netdev,
                     struct match *match, struct nlattr *actions,
                     size_t actions_len, const ovs_u128 *ufid,
                     odp_port_t orig_in_port OVS_UNUSED,
                     void **previous_flow_reference,
                     struct dpif_flow_stats *stats)
{
    struct ufid_to_doh_data *old_doh_data;
    struct ufid_to_doh_data *doh_data;
    struct pmd_data *pmd_mapping;
    bool modification = false;
    bool pmd_exists;
    int ret;

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    /* If an old doh_data exists for this pmd_id, it means it's a flow
     * modification.  Here destroy the old doh_data first before adding a
     * new one.  Keep the stats and pmd_mapping for the newly created rule. */
    old_doh_data = ufid_to_doh_data_find_pmd_and_update(
        netdev, ufid, pmd_id, &pmd_exists, flow_reference,
        previous_flow_reference);
    doh_data = old_doh_data;

    if (old_doh_data && old_doh_data->doh.e.entry && pmd_exists) {
        memcpy(&old_doh_data->baseline_stats, &old_doh_data->stats,
               sizeof old_doh_data->baseline_stats);
        modification = true;
        pmd_mapping = ovsrcu_get(struct pmd_data *,
                                 &old_doh_data->pmd_mapping);
        ovs_mutex_lock(&old_doh_data->lock);
        ovsrcu_set(&old_doh_data->pmd_mapping, NULL);

        ret = doh_data_destroy(offload, old_doh_data, false, true);
        ovs_mutex_unlock(&old_doh_data->lock);
        if (ret) {
            return ret;
        }
    } else if (!old_doh_data) {
        pmd_mapping = pmd_data_init();
        pmd_data_associate(pmd_mapping, pmd_id, flow_reference);
        *previous_flow_reference = NULL;
    } else /* if (old_doh_data) */ {
        pmd_mapping = ovsrcu_get(struct pmd_data *,
                                 &old_doh_data->pmd_mapping);

        pmd_data_associate(pmd_mapping, pmd_id, flow_reference);
        *previous_flow_reference = NULL;
    }

    if (modification || !old_doh_data) {
        doh_data = doca_offload_add_flow(offload, pmd_mapping, netdev, match,
                                         actions, actions_len, ufid,
                                         old_doh_data);
        if (!doh_data) {
            if (modification) {
                ovs_mutex_lock(&old_doh_data->lock);
                ufid_to_doh_disassociate(old_doh_data);
                ovs_mutex_unlock(&old_doh_data->lock);
            }

            /* Clean up existing mappings, except for the current pmd_id one,
             * as this is handled through the callback. */
            pmd_data_disassociate(pmd_mapping, pmd_id);
            pmd_data_cleanup(offload, pmd_mapping);
            ovsrcu_postpone(pmd_data_destroy, pmd_mapping);
            return EINVAL;
        }
    }

    if (modification) {
        memcpy(&doh_data->stats, &old_doh_data->baseline_stats,
               sizeof doh_data->stats);
    }

    if (stats) {
        *stats = doh_data->stats;
    }

    return 0;
}

int
doca_netdev_flow_del(struct doca_offload *offload, struct netdev *netdev,
                     unsigned pmd_id, const ovs_u128 *ufid,
                     void *flow_reference, struct dpif_flow_stats *stats)
{
    struct ufid_to_doh_data *doh_data;

    doh_data = ufid_to_doh_data_find(netdev, ufid);
    if (!doh_data || !doh_data->doh.e.entry) {
        return ENOENT;
    }

    if (!pmd_data_find_and_delete(doh_data, pmd_id, flow_reference)) {
        return ENOENT;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    return doh_data_destroy(offload, doh_data, false, false);
}

int
doca_netdev_offload_init(struct netdev *netdev,
                         unsigned int offload_thread_count)
{
    return offload_data_init(netdev, offload_thread_count);
}

void
doca_netdev_offload_uninit(struct netdev *netdev)
{
    offload_data_destroy(netdev);
}

int
doca_netdev_flow_get(struct netdev *netdev, struct match *match OVS_UNUSED,
                     struct nlattr **actions OVS_UNUSED, const ovs_u128 *ufid,
                     struct dpif_flow_stats *stats,
                     struct dpif_flow_attrs *attrs,
                     struct ofpbuf *buf OVS_UNUSED)
{
    struct doca_flow_resource_query query;
    struct ufid_to_doh_data *doh_data;
    int ret = 0;

    attrs->dp_extra_info = NULL;

    doh_data = ufid_to_doh_data_find(netdev, ufid);
    if (doh_data) {
        attrs->offloaded = true;
    }

    if (!doh_data || !doh_data->doh.e.entry ||
        doh_data->dead || ovs_mutex_trylock(&doh_data->lock)) {
        if (doh_data) {
            attrs->dp_layer = "doca";
            /* The node might be in the process of being deleted.
             * It should be fine to read from it as actual freeing is done
             * after an RCU grace period. */
            memcpy(stats, &doh_data->stats, sizeof *stats);
            return 0;
        }

        return ENOENT;
    }

    /* Check again whether the data is dead, as it could have been
     * updated while the lock was not yet taken.  The first check above
     * was only to avoid unnecessary locking if possible. */
    if (doh_data->dead) {
        ret = ENOENT;
        goto out;
    }

    attrs->offloaded = true;
    attrs->dp_layer = "doca";

    ret = doca_flow_resource_query_entry(doh_data->doh.e.entry, &query);
    if (ret) {
        VLOG_DBG_RL(&rl, "%s: Failed to query ufid "UUID_FMT" entry: %p",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *) ufid),
                    doh_data->doh.e.entry);
        goto out;
    }

    if (doh_data->stats.n_packets != query.counter.total_pkts) {
        doh_data->stats.used = time_msec();
    }

    doh_data->stats.n_packets = query.counter.total_pkts +
        doh_data->baseline_stats.n_packets;
    doh_data->stats.n_bytes = query.counter.total_bytes +
        doh_data->baseline_stats.n_bytes;
    memcpy(stats, &doh_data->stats, sizeof *stats);
out:
    ovs_mutex_unlock(&doh_data->lock);
    return ret;
}

static void
doca_netdev_flow_flush__(struct doca_offload *offload, struct netdev *netdev)
{
    struct cmap *map = offload_data_map(netdev);
    unsigned int tid = doca_offload_thread_id();
    struct ufid_to_doh_data *data;

    if (!map) {
        return;
    }

    CMAP_FOR_EACH (data, node, map) {
        if (data->creation_tid == tid) {
            doh_data_destroy(offload, data, true, false);
        }
    }
}

struct flush_related_aux {
    struct doca_offload *offload;
    struct netdev *netdev;
};

static bool
flush_related_cb(struct netdev *related,
                 odp_port_t odp_port OVS_UNUSED,
                 void *aux_)
{
    struct doca_offload_esw_data *offload_data;
    struct flush_related_aux *aux = aux_;

    if (aux->netdev == related) {
        return false;
    }

    offload_data = netdev_doca_get_esw_offload_data(related);
    /* Representors are related. */
    if (netdev_doca_is_esw_mgr(aux->netdev) &&
        offload_data == netdev_doca_get_esw_offload_data(aux->netdev)) {
        doca_netdev_flow_flush__(aux->offload, related);
    }

    return false;
}

int
doca_netdev_flow_flush(struct doca_offload *offload, struct netdev *netdev)
{
    struct flush_related_aux aux = {
        .offload = offload,
        .netdev = netdev,
    };

    doca_netdev_flow_flush__(offload, netdev);
    doca_offload_traverse_ports(offload, flush_related_cb, &aux);

    return 0;
}

int
doca_netdev_hw_miss_packet_recover(struct doca_offload *offload OVS_UNUSED,
                                   struct netdev *netdev OVS_UNUSED,
                                   unsigned pmd_id OVS_UNUSED,
                                   struct dp_packet *packet OVS_UNUSED,
                                   void **flow_reference OVS_UNUSED)
{
    return 0;
}

uint64_t
doca_netdev_flow_count(struct netdev *netdev,
                       unsigned int offload_thread_count)
{
    struct doca_offload_netdev_data *data;
    uint64_t total = 0;
    unsigned int tid;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (!data) {
        return 0;
    }

    for (tid = 0; tid < 1 + offload_thread_count; tid++) {
        total += data->doh_counters[tid];
    }

    return total;
}

uint64_t
doca_netdev_flow_count_by_thread(struct netdev *netdev, unsigned int tid)
{
    struct doca_offload_netdev_data *data;

    data = (struct doca_offload_netdev_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (!data) {
        return 0;
    }

    return data->doh_counters[tid];
}

void
doca_netdev_offload_start(struct netdev *netdev)
{
    doca_pipe_group_init(netdev);
}

void
doca_netdev_offload_stop(struct netdev *netdev)
{
    doca_pipe_group_uninit(netdev);
}
