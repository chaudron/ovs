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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "netdev-offload-dpdk.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"

#include "openvswitch/json.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_dpdk);

#define DEFAULT_OFFLOAD_THREAD_NB 1
#define MAX_OFFLOAD_THREAD_NB 10

static unsigned int offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;

/* dpif offload interface for the dpdk rte_flow implementation. */
struct dpif_offload_dpdk {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_dpdk *
dpif_offload_dpdk_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_dpdk_class);
    return CONTAINER_OF(offload, struct dpif_offload_dpdk, offload);
}

static int
dpif_offload_dpdk_enable_offload(struct dpif_offload *offload_,
                                 struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, offload_);
    return 0;
}

static int
dpif_offload_dpdk_cleanup_offload(struct dpif_offload *offload_ OVS_UNUSED,
                                  struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

static int
dpif_offload_dpdk_port_add(struct dpif_offload *offload_,
                           struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);

    if (dpif_offload_port_mgr_add(offload->port_mgr, port, netdev,
                                  port_no, false)) {
        if (dpif_offload_is_offload_enabled()) {
            return dpif_offload_dpdk_enable_offload(offload_, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static int
dpif_offload_dpdk_port_del(struct dpif_offload *offload_, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_remove(offload->port_mgr, port_no, true);
    if (port) {
        if (dpif_offload_is_offload_enabled()) {
            ret = dpif_offload_dpdk_cleanup_offload(offload_, port);
        }
        netdev_close(port->netdev);
        ovsrcu_postpone(free, port);
    }
    return ret;
}

static int
dpif_offload_dpdk_open(const struct dpif_offload_class *offload_class,
                       struct dpif *dpif, struct dpif_offload **offload_)
{
    struct dpif_offload_dpdk *offload;

    offload = xmalloc(sizeof(struct dpif_offload_dpdk));

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->port_mgr = dpif_offload_port_mgr_init();
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;

    *offload_ = &offload->offload;
    return 0;
}

static bool
dpif_offload_dpdk_cleanup_port(struct dpif_offload_port_mgr_port *port,
                               void *aux)
{
    struct dpif_offload *offload_ = aux;

    dpif_offload_dpdk_port_del(offload_, port->port_no);
    return false;
}

static void
dpif_offload_dpdk_close(struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    dpif_offload_port_mgr_traverse_ports(offload->port_mgr,
                                         dpif_offload_dpdk_cleanup_port,
                                         offload_);

    dpif_offload_port_mgr_uninit(offload->port_mgr);
    free(offload);
}

static bool dpif_offload_dpdk_late_enable(struct dpif_offload_port_mgr_port *p,
                                          void *aux)
{
    struct dpif_offload *offload_ = aux;

    dpif_offload_dpdk_enable_offload(offload_, p);
    return false;
}

static void
dpif_offload_dpdk_set_config(struct dpif_offload *offload_,
                             const struct smap *other_cfg)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    /* We maintain the existing behavior where global configurations
     * are only accepted when hardware offload is initially enabled.
     * Once enabled, they cannot be updated or reconfigured. */
    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {

            offload_thread_nb = smap_get_ullong(other_cfg,
                                                "n-offload-threads",
                                                DEFAULT_OFFLOAD_THREAD_NB);
            if (offload_thread_nb == 0 ||
                offload_thread_nb > MAX_OFFLOAD_THREAD_NB) {
                VLOG_WARN("netdev: Invalid number of threads requested: %u",
                          offload_thread_nb);
                offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;
            }

            if (smap_get(other_cfg, "n-offload-threads")) {
                VLOG_INFO("Flow API using %u thread%s",
                          offload_thread_nb,
                          offload_thread_nb > 1 ? "s" : "");
            }

            dpif_offload_port_mgr_traverse_ports(offload->port_mgr,
                                                 dpif_offload_dpdk_late_enable,
                                                 offload);

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static bool
dpif_offload_dpdk_get_port_debug_ds(struct dpif_offload_port_mgr_port *port,
                                    void *aux)
{
    struct ds *ds = aux;

    ds_put_format(ds, "  - %s: port_no: %u\n",
                  netdev_get_name(port->netdev), port->port_no);

    return false;
}

static bool
dpif_offload_dpdk_get_port_debug_json(struct dpif_offload_port_mgr_port *port,
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
dpif_offload_dpdk_get_debug(const struct dpif_offload *offload_, struct ds *ds,
                            struct json *json)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    if (json) {
        struct json *json_ports = json_object_create();

        dpif_offload_port_mgr_traverse_ports(
            offload->port_mgr, dpif_offload_dpdk_get_port_debug_json,
            json_ports);

        if (!json_object_is_empty(json_ports)) {
            json_object_put(json, "ports", json_ports);
        } else {
            json_destroy(json_ports);
        }

    } else if (ds) {
        dpif_offload_port_mgr_traverse_ports(
            offload->port_mgr, dpif_offload_dpdk_get_port_debug_ds, ds);
    }
}

static bool
dpif_offload_dpdk_can_offload(struct dpif_offload *offload OVS_UNUSED,
                              struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class)
          && strcmp(netdev_get_dpif_type(netdev), "netdev")) {
        VLOG_DBG("%s: vport doesn't belong to the netdev datapath, skipping",
                 netdev_get_name(netdev));
        return false;
    }

    return netdev_dpdk_flow_api_supported(netdev, true);
}

static bool
dpif_offload_dpdk_get_n_offloaded_cb(
    struct dpif_offload_port_mgr_port *port, void *aux)
{
    uint64_t *total = aux;

    *total += netdev_offload_dpdk_flow_get_n_offloaded(port->netdev);
    return false;
}

static uint64_t
dpif_offload_dpdk_get_n_offloaded(const struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    uint64_t total = 0;

    if (!dpif_offload_is_offload_enabled()) {
        return 0;
    }

    dpif_offload_port_mgr_traverse_ports(
        offload->port_mgr, dpif_offload_dpdk_get_n_offloaded_cb, &total);

    return total;
}

static int
dpif_offload_dpdk_netdev_flow_flush(const struct dpif_offload *offload
                                    OVS_UNUSED, struct netdev *netdev)
{
    return netdev_offload_dpdk_flow_flush(netdev);
}

static int
dpif_offload_dpdk_netdev_hw_miss_packet_postprocess(
    const struct dpif_offload *offload_ OVS_UNUSED, struct netdev *netdev,
    struct dp_packet *packet)
{
    return netdev_offload_dpdk_hw_miss_packet_recover(netdev, packet);
}

struct dpif_offload_class dpif_offload_dpdk_class = {
    .type = "dpdk",
    .supported_dpif_types = (const char *const[]) {
        "netdev",
        NULL},
    .open = dpif_offload_dpdk_open,
    .close = dpif_offload_dpdk_close,
    .set_config = dpif_offload_dpdk_set_config,
    .get_debug = dpif_offload_dpdk_get_debug,
    .can_offload = dpif_offload_dpdk_can_offload,
    .port_add = dpif_offload_dpdk_port_add,
    .port_del = dpif_offload_dpdk_port_del,
    .flow_get_n_offloaded = dpif_offload_dpdk_get_n_offloaded,
    .netdev_flow_flush = dpif_offload_dpdk_netdev_flow_flush,
    .netdev_hw_miss_packet_postprocess = \
        dpif_offload_dpdk_netdev_hw_miss_packet_postprocess,
};

/* XXX: Temporary functions below, which will be removed once fully
 *      refactored. */
unsigned int dpif_offload_dpdk_get_thread_nb(void);
unsigned int dpif_offload_dpdk_get_thread_nb(void)
{
    return offload_thread_nb;
}
