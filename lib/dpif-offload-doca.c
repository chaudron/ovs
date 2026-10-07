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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dpif-offload-doca-private.h"
#include "ovs-rcu.h"

/* dpif offload interface for the doca offload implementation. */
struct doca_offload {
    struct dpif_offload offload;

    atomic_count next_offload_thread_id;
    atomic_bool offload_thread_shutdown;
    struct doca_offload_thread *offload_threads;

    dpif_offload_flow_unreference_cb *unreference_cb;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
    unsigned int offload_thread_count; /* Number of offload threads. */
};

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, doca_offload_thread_id);
DEFINE_EXTERN_PER_THREAD_DATA(doca_offload_thread_id, OVSTHREAD_ID_UNSET);

unsigned int
doca_offload_thread_id(void)
{
    unsigned int id = *doca_offload_thread_id_get();

    if (OVS_UNLIKELY(id == OVSTHREAD_ID_UNSET)) {
        /* Offload threads get their ID set at initialization, here
         * only the RCU thread might need initialization. */
        ovs_assert(!strncmp(get_subprogram_name(), "urcu", strlen("urcu")));

        /* RCU will compete with other threads for shared object access.
         * Reclamation functions using a thread ID must be thread-safe.
         * For that end, and because RCU must consider all potential shared
         * objects anyway, its thread-id can be whichever, so return 0. */
        id = 0;
        *doca_offload_thread_id_get() = id;
    }

    return id;
}

void
doca_offload_traverse_ports(const struct doca_offload *offload,
                            bool (*cb)(struct netdev *, odp_port_t, void *),
                            void *aux)
{
    struct dpif_offload_port *port;

    DPIF_OFFLOAD_PORT_FOR_EACH (port, &offload->offload) {
        if (cb(port->netdev, port->port_no, aux)) {
            break;
        }
    }
}

static struct netdev *
doca_offload_get_netdev__(const struct dpif_offload *offload,
                          odp_port_t port_no)
{
    struct dpif_offload_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(offload, port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

struct netdev *
doca_offload_get_netdev(const struct doca_offload *offload, odp_port_t port_no)
{
    return doca_offload_get_netdev__(&offload->offload, port_no);
}

void
doca_offload_unreference(struct doca_offload *offload, unsigned pmd_id,
                         void *flow_reference)
{
    if (offload->unreference_cb) {
        offload->unreference_cb(pmd_id, flow_reference);
    }
}
