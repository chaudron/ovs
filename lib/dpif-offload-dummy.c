/*
 * Copyright (c) 2025 Red Hat, Inc.
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
 #include <errno.h>

#include "dpif.h"
#include "dpif-offload-provider.h"
#include "dpif-offload.h"
#include "dummy.h"
#include "id-fpool.h"
#include "netdev-provider.h"
#include "odp-util.h"
#include "util.h"
#include "uuid.h"

#include "openvswitch/json.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_dummy);

struct dummy_offloaded_flow {
    struct hmap_node node;
    struct match match;
    ovs_u128 ufid;
    uint32_t mark;
};

struct dpif_offload_dummy {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    struct id_fpool *flow_mark_pool;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

struct dpif_offload_dummy_port {
    struct dpif_offload_port_mgr_port pm_port;

    struct ovs_mutex port_mutex; /* Protect all below members. */
    struct hmap offloaded_flows OVS_GUARDED;
};

static uint32_t
dpif_offload_dummy_allocate_flow_mark(struct dpif_offload_dummy *offload_dummy)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    uint32_t flow_mark;

    if (ovsthread_once_start(&init_once)) {
        /* Haven't initiated yet, do it here. */
        offload_dummy->flow_mark_pool = id_fpool_create(1, 1, UINT32_MAX - 1);
        ovsthread_once_done(&init_once);
    }

    if (id_fpool_new_id(offload_dummy->flow_mark_pool, 0, &flow_mark)) {
        return flow_mark;
    }

    return INVALID_FLOW_MARK;
}

static void
dpif_offload_dummy_free_flow_mark(struct dpif_offload_dummy *offload_dummy,
                                  uint32_t flow_mark)
{
    if (flow_mark != INVALID_FLOW_MARK) {
        id_fpool_free_id(offload_dummy->flow_mark_pool, 0, flow_mark);
    }
}

static struct dpif_offload_dummy_port *
dpif_offload_dummy_cast_port(struct dpif_offload_port_mgr_port *port)
{
    return CONTAINER_OF(port, struct dpif_offload_dummy_port, pm_port);
}

static struct dpif_offload_dummy *
dpif_offload_dummy_cast(const struct dpif_offload *offload)
{
    return CONTAINER_OF(offload, struct dpif_offload_dummy, offload);
}

static uint32_t
dpif_offload_dummy_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

static struct dummy_offloaded_flow *
dpif_offload_dummy_find_offloaded_flow(const struct hmap *offloaded_flows,
                                       const ovs_u128 *ufid)
{
    uint32_t hash = dpif_offload_dummy_flow_hash(ufid);
    struct dummy_offloaded_flow *data;

    HMAP_FOR_EACH_WITH_HASH (data, node, hash, offloaded_flows) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static void
dpif_offload_dummy_enable_offload(struct dpif_offload *dpif_offload,
                                  struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, dpif_offload);
}

static void
dpif_offload_dummy_cleanup_offload(
    struct dpif_offload *dpif_offload OVS_UNUSED,
    struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
}


static void
dpif_offload_dummy_free_port(struct dpif_offload_dummy_port *port)
{
    struct dummy_offloaded_flow *off_flow;

    ovs_mutex_lock(&port->port_mutex);
    HMAP_FOR_EACH_POP (off_flow, node, &port->offloaded_flows) {
        free(off_flow);
    }
    hmap_destroy(&port->offloaded_flows);
    ovs_mutex_unlock(&port->port_mutex);
    ovs_mutex_destroy(&port->port_mutex);
    free(port);
}

static int
dpif_offload_dummy_port_add(struct dpif_offload *dpif_offload,
                            struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_dummy_port *port = xmalloc(sizeof *port);
    struct dpif_offload_dummy *offload_dummy;

    ovs_mutex_init(&port->port_mutex);
    ovs_mutex_lock(&port->port_mutex);
    hmap_init(&port->offloaded_flows);
    ovs_mutex_unlock(&port->port_mutex);

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);
    if (dpif_offload_port_mgr_add(offload_dummy->port_mgr, &port->pm_port,
                                  netdev, port_no, false)) {

        if (dpif_offload_is_offload_enabled()) {
            dpif_offload_dummy_enable_offload(dpif_offload, &port->pm_port);
        }
        return 0;
    }

    dpif_offload_dummy_free_port(port);
    return EEXIST;
}

static int
dpif_offload_dummy_port_del(struct dpif_offload *dpif_offload,
                            odp_port_t port_no)
{
    struct dpif_offload_dummy *offload_dummy;
    struct dpif_offload_port_mgr_port *port;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    port = dpif_offload_port_mgr_remove(offload_dummy->port_mgr, port_no,
                                        true);
    if (port) {
        struct dpif_offload_dummy_port *dummy_port;

        dummy_port = dpif_offload_dummy_cast_port(port);
        if (dpif_offload_is_offload_enabled()) {
            dpif_offload_dummy_cleanup_offload(dpif_offload, port);
        }
        netdev_close(port->netdev);

        ovsrcu_postpone(dpif_offload_dummy_free_port, dummy_port);
    }
    return 0;
}

static int
dpif_offload_dummy_port_dump_start(const struct dpif_offload *offload_,
                                      void **statep)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);

    return dpif_offload_port_mgr_port_dump_start(offload->port_mgr, statep);
}

static int
dpif_offload_dummy_port_dump_next(const struct dpif_offload *offload_,
                                  void *state,
                                  struct dpif_offload_port *port)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);

    return dpif_offload_port_mgr_port_dump_next(offload->port_mgr, state,
                                                port);
}

static int
dpif_offload_dummy_port_dump_done(const struct dpif_offload *offload_,
                                  void *state)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);

    return dpif_offload_port_mgr_port_dump_done(offload->port_mgr, state);
}

static struct netdev *
dpif_offload_dummy_get_netdev(struct dpif_offload *dpif_offload,
                              odp_port_t port_no)
{
    struct dpif_offload_dummy *offload_dummy;
    struct dpif_offload_port_mgr_port *port;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    port = dpif_offload_port_mgr_find_by_odp_port(offload_dummy->port_mgr,
                                                  port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static int
dpif_offload_dummy_open(const struct dpif_offload_class *offload_class,
                        struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = xmalloc(sizeof(struct dpif_offload_dummy));

    dpif_offload_init(&offload_dummy->offload, offload_class, dpif);
    offload_dummy->port_mgr = dpif_offload_port_mgr_init();
    offload_dummy->once_enable = (struct ovsthread_once)
        OVSTHREAD_ONCE_INITIALIZER;
    offload_dummy->flow_mark_pool = NULL;

    *dpif_offload = &offload_dummy->offload;
    return 0;
}

static bool
dpif_offload_dummy_cleanup_port(struct dpif_offload_port_mgr_port *port,
                                void *aux)
{
    struct dpif_offload *offload = aux;

    dpif_offload_dummy_port_del(offload, port->port_no);
    return false;
}

static void
dpif_offload_dummy_close(struct dpif_offload *dpif_offload)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    /* The ofproto layer may not call dpif_port_del() for all ports,
     * especially internal ones, so we need to clean up any remaining ports. */
    dpif_offload_port_mgr_traverse_ports(offload_dummy->port_mgr,
                                         dpif_offload_dummy_cleanup_port,
                                         dpif_offload);

    dpif_offload_port_mgr_uninit(offload_dummy->port_mgr);
    if (offload_dummy->flow_mark_pool) {
        id_fpool_destroy(offload_dummy->flow_mark_pool);
    }
    free(offload_dummy);
}

static bool
dpif_offload_dummy_late_enable(struct dpif_offload_port_mgr_port *port,
                               void *aux)
{
    dpif_offload_dummy_enable_offload(aux, port);
    return false;
}

static void
dpif_offload_dummy_set_config(struct dpif_offload *dpif_offload,
                              const struct smap *other_cfg)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    /* We maintain the existing behavior where global configurations
     * are only accepted when hardware offload is initially enabled.
     * Once enabled, they cannot be updated or reconfigured. */
    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload_dummy->once_enable)) {

            dpif_offload_port_mgr_traverse_ports(
                offload_dummy->port_mgr, dpif_offload_dummy_late_enable,
                dpif_offload);

            ovsthread_once_done(&offload_dummy->once_enable);
        }
    }
}

static bool
dpif_offload_dummy_get_port_debug_ds(struct dpif_offload_port_mgr_port *port,
                                     void *aux)
{
    struct ds *ds = aux;

    ds_put_format(ds, "  - %s: port_no: %u\n", netdev_get_name(port->netdev),
                  port->port_no);

    return false;
}

static bool
dpif_offload_dummy_get_port_debug_json(struct dpif_offload_port_mgr_port *port,
                                     void *aux)
{
    struct json *json_port = json_object_create();
    struct json *json = aux;

    json_object_put(json_port, "port_no",
                    json_integer_create(odp_to_u32(port->port_no)));

    json_object_put(json, netdev_get_name(port->netdev), json_port);
    return false;
}

static void
dpif_offload_dummy_get_debug(const struct dpif_offload *offload, struct ds *ds,
                             struct json *json)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(offload);

    if (json) {
        struct json *json_ports = json_object_create();

        dpif_offload_port_mgr_traverse_ports(
            offload_dummy->port_mgr, dpif_offload_dummy_get_port_debug_json,
            json_ports);

        if (!json_object_is_empty(json_ports)) {
            json_object_put(json, "ports", json_ports);
        } else {
            json_destroy(json_ports);
        }

    } else if (ds) {
        dpif_offload_port_mgr_traverse_ports(
            offload_dummy->port_mgr, dpif_offload_dummy_get_port_debug_ds, ds);
    }
}

static int
dpif_offload_dummy_get_global_stats(const struct dpif_offload *offload_,
                                    struct netdev_custom_stats *stats)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);

    /* Add a single counter telling how many ports we are servicing. */
    stats->label = xstrdup(dpif_offload_name(offload_));
    stats->size = 1;
    stats->counters = xmalloc(sizeof(struct netdev_custom_counter) * 1);
    stats->counters[0].value = dpif_offload_port_mgr_port_count(
        offload->port_mgr);
    ovs_strzcpy(stats->counters[0].name, "Offloaded port count",
                sizeof stats->counters[0].name);

    return 0;
}

static bool
dpif_offload_dummy_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                               struct netdev *netdev)
{
    return is_dummy_netdev_class(netdev->netdev_class) ? true : false;
}

static void
dpif_offload_dummy_log_operation(const char *op, int error,
                                 const ovs_u128 *ufid)
{
    VLOG_DBG("%s to %s netdev flow "UUID_FMT,
             error == 0 ? "succeed" : "failed", op,
             UUID_ARGS((struct uuid *) ufid));
}

static struct dpif_offload_dummy_port *
dpif_offload_dummy_get_port_by_netdev(const struct dpif_offload *offload_,
                                      struct netdev *netdev)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);
    struct dpif_offload_port_mgr_port *port;

    port = dpif_offload_port_mgr_find_by_netdev(offload->port_mgr, netdev);
    if (!port) {
        return NULL;
    }
    return dpif_offload_dummy_cast_port(port);
}

static int
dpif_offload_dummy_netdev_flow_put(const struct dpif_offload *offload_,
                                   struct netdev *netdev,
                                   struct dpif_offload_flow_put *put)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);
    struct dummy_offloaded_flow *off_flow;
    struct dpif_offload_dummy_port *port;
    bool modify = true;
    int error = 0;

    port = dpif_offload_dummy_get_port_by_netdev(offload_, netdev);
    if (!port) {
        error = ENODEV;
        goto exit;
    }

    ovs_mutex_lock(&port->port_mutex);

    off_flow = dpif_offload_dummy_find_offloaded_flow(&port->offloaded_flows,
                                                      put->ufid);
    if (!off_flow) {
        /* Create new offloaded flow. */
        uint32_t mark = dpif_offload_dummy_allocate_flow_mark(offload);

        if (mark == INVALID_FLOW_MARK) {
            error = ENOSPC;
            goto exit_unlock;
        }

        off_flow = xzalloc(sizeof *off_flow);
        off_flow->mark = mark;
        memcpy(&off_flow->ufid, put->ufid, sizeof *put->ufid);
        hmap_insert(&port->offloaded_flows, &off_flow->node,
                    dpif_offload_dummy_flow_hash(put->ufid));
        modify = false;
    }
    memcpy(&off_flow->match, put->match, sizeof *put->match);

    /* As we have per-netdev 'offloaded_flows', we don't need to match
     * the 'in_port' for received packets.  This will also allow offloading
     * for packets passed to 'receive' command without specifying the
     * 'in_port'. */
    off_flow->match.wc.masks.in_port.odp_port = 0;

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s: flow put[%s]: ", netdev_get_name(netdev),
                      modify ? "modify" : "create");
        odp_format_ufid(put->ufid, &ds);
        ds_put_cstr(&ds, " flow match: ");
        match_format(put->match, NULL, &ds, OFP_DEFAULT_PRIORITY);
        ds_put_format(&ds, ", mark: %"PRIu32, off_flow->mark);

        VLOG_DBG("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

exit_unlock:
    ovs_mutex_unlock(&port->port_mutex);

exit:
    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }

    dpif_offload_dummy_log_operation(put->modify ? "modify" : "add", error,
                                     put->ufid);
    return error;
}

static int
dpif_offload_dummy_netdev_flow_del(const struct dpif_offload *offload_,
                                   struct netdev *netdev,
                                   struct dpif_offload_flow_del *del)
{
    struct dpif_offload_dummy *offload = dpif_offload_dummy_cast(offload_);
    struct dummy_offloaded_flow *off_flow;
    struct dpif_offload_dummy_port *port;
    uint32_t mark = INVALID_FLOW_MARK;
    const char *error = NULL;

    port = dpif_offload_dummy_get_port_by_netdev(offload_, netdev);
    if (!port) {
        error = "No such (net)device.";
        goto exit;
    }

    ovs_mutex_lock(&port->port_mutex);

    off_flow = dpif_offload_dummy_find_offloaded_flow(&port->offloaded_flows,
                                                      del->ufid);
    if (!off_flow) {
        error = "No such flow.";
        goto exit_unlock;
    }

    mark = off_flow->mark;
    hmap_remove(&port->offloaded_flows, &off_flow->node);
    dpif_offload_dummy_free_flow_mark(offload, mark);
    free(off_flow);

exit_unlock:
    ovs_mutex_unlock(&port->port_mutex);

exit:
    if (error || VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s: ", netdev_get_name(netdev));
        if (error) {
            ds_put_cstr(&ds, "failed to ");
        }
        ds_put_cstr(&ds, "flow del: ");
        odp_format_ufid(del->ufid, &ds);
        if (error) {
            ds_put_format(&ds, " error: %s", error);
        } else {
            ds_put_format(&ds, " mark: %"PRIu32, mark);
        }
        VLOG(error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    dpif_offload_dummy_log_operation("delete", error ? -1 : 0, del->ufid);
    return error ? ENOENT : 0;
}

static bool
dpif_offload_dummy_netdev_flow_stats(const struct dpif_offload *offload_,
                                     struct netdev *netdev,
                                     const ovs_u128 *ufid,
                                     struct dpif_flow_stats *stats,
                                     struct dpif_flow_attrs *attrs)
{
    struct dummy_offloaded_flow *off_flow = NULL;
    struct dpif_offload_dummy_port *port;

    port = dpif_offload_dummy_get_port_by_netdev(offload_, netdev);
    if (!port) {
        return false;
    }

    ovs_mutex_lock(&port->port_mutex);
    off_flow = dpif_offload_dummy_find_offloaded_flow(&port->offloaded_flows,
                                                      ufid);
    ovs_mutex_unlock(&port->port_mutex);

    memset(stats, 0, sizeof *stats);
    attrs->offloaded = off_flow ? true : false;
    attrs->dp_layer = "tc";
    attrs->dp_extra_info = NULL;

    return off_flow ? true : false;
}

void
dpif_offload_dummy_netdev_simulate_offload(struct netdev *netdev,
                                           struct dp_packet *packet,
                                           struct flow *flow)
{
    const struct dpif_offload *offload_ = ovsrcu_get(
        const struct dpif_offload *, &netdev->dpif_offload);
    struct dpif_offload_dummy_port *port;
    struct dummy_offloaded_flow *data;
    struct flow packet_flow;

    if (!offload_ || strcmp(dpif_offload_class_type(offload_), "dummy")) {
        return;
    }

    port = dpif_offload_dummy_get_port_by_netdev(offload_, netdev);
    if (!port) {
        return;
    }

    if (!flow) {
        flow = &packet_flow;
        flow_extract(packet, flow);
    }

    ovs_mutex_lock(&port->port_mutex);
    HMAP_FOR_EACH (data, node, &port->offloaded_flows) {
        if (flow_equal_except(flow, &data->match.flow, &data->match.wc)) {

            dp_packet_set_flow_mark(packet, data->mark);

            if (VLOG_IS_DBG_ENABLED()) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ds_put_format(&ds, "%s: packet: ",
                              netdev_get_name(netdev));
                /* 'flow' does not contain proper port number here.
                 * Let's just clear it as it's wildcarded anyway. */
                flow->in_port.ofp_port = 0;
                flow_format(&ds, flow, NULL);

                ds_put_cstr(&ds, " matches with flow: ");
                odp_format_ufid(&data->ufid, &ds);
                ds_put_cstr(&ds, " ");
                match_format(&data->match, NULL, &ds, OFP_DEFAULT_PRIORITY);
                ds_put_format(&ds, " with mark: %"PRIu32, data->mark);

                VLOG_DBG("%s", ds_cstr(&ds));
                ds_destroy(&ds);
            }
            break;
        }
    }
    ovs_mutex_unlock(&port->port_mutex);
}

#define DEFINE_DPIF_DUMMY_CLASS(NAME, TYPE_STR)                    \
    struct dpif_offload_class NAME = {                             \
        .type = TYPE_STR,                                          \
        .impl_type = DPIF_OFFLOAD_IMPL_HW_ONLY,                    \
        .supported_dpif_types = (const char *const[]){             \
            "dummy",                                               \
            NULL},                                                 \
        .open = dpif_offload_dummy_open,                           \
        .close = dpif_offload_dummy_close,                         \
        .set_config = dpif_offload_dummy_set_config,               \
        .get_debug = dpif_offload_dummy_get_debug,                 \
        .get_global_stats = dpif_offload_dummy_get_global_stats,   \
        .can_offload = dpif_offload_dummy_can_offload,             \
        .port_add = dpif_offload_dummy_port_add,                   \
        .port_del = dpif_offload_dummy_port_del,                   \
        .port_dump_start = dpif_offload_dummy_port_dump_start,     \
        .port_dump_next = dpif_offload_dummy_port_dump_next,       \
        .port_dump_done = dpif_offload_dummy_port_dump_done,       \
        .get_netdev = dpif_offload_dummy_get_netdev,               \
        .netdev_flow_put = dpif_offload_dummy_netdev_flow_put,     \
        .netdev_flow_del = dpif_offload_dummy_netdev_flow_del,     \
        .netdev_flow_stats = dpif_offload_dummy_netdev_flow_stats, \
}

DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_class, "dummy");
DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_x_class, "dummy_x");
