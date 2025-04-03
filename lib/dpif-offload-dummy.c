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

#include "dpif-offload-provider.h"
#include "dpif-offload.h"
#include "dummy.h"
#include "netdev-provider.h"
#include "util.h"


struct dpif_offload_dummy {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_dummy *
dpif_offload_dummy_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_dummy_class);
    return CONTAINER_OF(offload, struct dpif_offload_dummy, offload);
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

static int
dpif_offload_dummy_port_add(struct dpif_offload *dpif_offload,
                            struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);
    if (dpif_offload_port_mgr_add(offload_dummy->port_mgr, port, netdev,
                                  port_no, false)) {

        if (dpif_offload_is_offload_enabled()) {
            dpif_offload_dummy_enable_offload(dpif_offload, port);
        }
        return 0;
    }

    free(port);
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
        if (dpif_offload_is_offload_enabled()) {
            dpif_offload_dummy_cleanup_offload(dpif_offload, port);
        }
        netdev_close(port->netdev);
        ovsrcu_postpone(free, port);
    }
    return 0;
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
    free(offload_dummy);
}

static bool dpif_offload_dummy_late_enable(
    struct dpif_offload_port_mgr_port *port, void *aux)
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
dpif_offload_dummy_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                               struct netdev *netdev)
{
    return is_dummy_netdev_class(netdev->netdev_class) ? true : false;
}

struct dpif_offload_class dpif_offload_dummy_class = {
    .type = "dummy",
    .supported_dpif_types = (const char *const[]) {
        "system",
        "netdev",
        "dummy",
        NULL},
    .open = dpif_offload_dummy_open,
    .close = dpif_offload_dummy_close,
    .set_config = dpif_offload_dummy_set_config,
    .can_offload = dpif_offload_dummy_can_offload,
    .port_add = dpif_offload_dummy_port_add,
    .port_del = dpif_offload_dummy_port_del,
};
