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
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_rte_flow);

#define DEFAULT_OFFLOAD_THREAD_NB 1
#define MAX_OFFLOAD_THREAD_NB 10

static unsigned int offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;

/* dpif offload interface for the rte implementation. */
struct dpif_offload_rte_flow {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_rte_flow *
dpif_offload_rte_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_rte_flow_class);
    return CONTAINER_OF(offload, struct dpif_offload_rte_flow, offload);
}

static int
dpif_offload_rte_enable_offload(struct dpif_offload *dpif_offload,
                                struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, dpif_offload);
    return 0;
}

static int
dpif_offload_rte_cleanup_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                                 struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

static int
dpif_offload_rte_port_add(struct dpif_offload *offload,
                          struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);

    if (dpif_offload_port_mgr_add(offload_rte->port_mgr, port, netdev,
                                  port_no, false)) {
        if (dpif_offload_is_offload_enabled()) {
            return dpif_offload_rte_enable_offload(offload, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static int
dpif_offload_rte_port_del(struct dpif_offload *offload, odp_port_t port_no)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);
    struct dpif_offload_port_mgr_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_remove(offload_rte->port_mgr, port_no, true);
    if (port) {
        if (dpif_offload_is_offload_enabled()) {
            ret = dpif_offload_rte_cleanup_offload(offload, port);
        }
        netdev_close(port->netdev);
        ovsrcu_postpone(free, port);
    }
    return ret;
}

static int
dpif_offload_rte_open(const struct dpif_offload_class *offload_class,
                      struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dpif_offload_rte_flow *offload_rte;

    offload_rte = xmalloc(sizeof(struct dpif_offload_rte_flow));

    dpif_offload_init(&offload_rte->offload, offload_class, dpif);
    offload_rte->port_mgr = dpif_offload_port_mgr_init();
    offload_rte->once_enable = (struct ovsthread_once)
        OVSTHREAD_ONCE_INITIALIZER;

    *dpif_offload = &offload_rte->offload;
    return 0;
}

static bool
dpif_offload_rte_cleanup_port(struct dpif_offload_port_mgr_port *port,
                              void *aux)
{
    struct dpif_offload *offload = aux;

    dpif_offload_rte_port_del(offload, port->port_no);
    return false;
}

static void
dpif_offload_rte_close(struct dpif_offload *dpif_offload)
{
    struct dpif_offload_rte_flow *offload_rte;

    offload_rte = dpif_offload_rte_cast(dpif_offload);

    dpif_offload_port_mgr_traverse_ports(offload_rte->port_mgr,
                                         dpif_offload_rte_cleanup_port,
                                         dpif_offload);

    dpif_offload_port_mgr_uninit(offload_rte->port_mgr);
    free(offload_rte);
}

static bool dpif_offload_rte_late_enable(struct dpif_offload_port_mgr_port *p,
                                         void *aux)
{
    dpif_offload_rte_enable_offload(aux, p);
    return false;
}

static void
dpif_offload_rte_set_config(struct dpif_offload *offload,
                           const struct smap *other_cfg)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);

    /* We maintain the existing behavior where global configurations
     * are only accepted when hardware offload is initially enabled.
     * Once enabled, they cannot be updated or reconfigured. */
    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload_rte->once_enable)) {

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

            dpif_offload_port_mgr_traverse_ports(offload_rte->port_mgr,
                                                 dpif_offload_rte_late_enable,
                                                 offload);

            ovsthread_once_done(&offload_rte->once_enable);
        }
    }
}

static bool
dpif_offload_rte_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
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

struct dpif_offload_class dpif_offload_rte_flow_class = {
    .type = "rte_flow",
    .supported_dpif_types = (const char *const[]) {
        "netdev",
        NULL},
    .open = dpif_offload_rte_open,
    .close = dpif_offload_rte_close,
    .set_config = dpif_offload_rte_set_config,
    .can_offload = dpif_offload_rte_can_offload,
    .port_add = dpif_offload_rte_port_add,
    .port_del = dpif_offload_rte_port_del,
};

/* XXX: Temporary functions below, which will be removed once fully
 *      refactored. */
unsigned int dpif_offload_rte_get_thread_nb(void);
unsigned int dpif_offload_rte_get_thread_nb(void)
{
    return offload_thread_nb;
}
