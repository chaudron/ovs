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
#include "dpif-provider.h"
#include "netdev-provider.h"
#include "unixctl.h"
#include "util.h"
#include "vswitch-idl.h"

#include "openvswitch/dynamic-string.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload);

static struct vlog_rate_limit rl_dbg = VLOG_RATE_LIMIT_INIT(1, 5);

static struct ovs_mutex dpif_offload_mutex = OVS_MUTEX_INITIALIZER;
static struct shash dpif_offload_classes \
    OVS_GUARDED_BY(dpif_offload_mutex) = \
    SHASH_INITIALIZER(&dpif_offload_classes);

static const struct dpif_offload_class *base_dpif_offload_classes[] = {
#if defined(__linux__)
    &dpif_offload_tc_class,
#endif
#ifdef DPDK_NETDEV
    &dpif_offload_rte_flow_class,
#endif
    /* If you add an offload class to this structure, make sure you also
     * update the dpif_offload_provider_priority_list below. */
    &dpif_offload_dummy_class,
    &dpif_offload_dummy_x_class,
};

static char *dpif_offload_provider_priority_list = "tc,rte_flow,dummy,dummy_x";
static atomic_bool dpif_offload_global_enabled = false;
static atomic_bool dpif_offload_rebalance_policy = false;
static struct smap port_order_cfg = SMAP_INITIALIZER(&port_order_cfg);

static int
dpif_offload_register_provider__(const struct dpif_offload_class *class)
    OVS_REQUIRES(dpif_offload_mutex)
{
    int error;

    if (shash_find(&dpif_offload_classes, class->type)) {
        VLOG_WARN("attempted to register duplicate dpif offload class: %s",
                  class->type);
        return EEXIST;
    }

    if (!class->supported_dpif_types) {
        VLOG_WARN("attempted to register a dpif offload class without any "
                  "supported dpifs: %s", class->type);
        return EINVAL;
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s dpif offload class: %s",
                  class->type, ovs_strerror(error));
        return error;
    }

    shash_add(&dpif_offload_classes, class->type, class);
    return 0;
}

static int
dpif_offload_register_provider(const struct dpif_offload_class *class)
{
    int error;

    ovs_mutex_lock(&dpif_offload_mutex);
    error = dpif_offload_register_provider__(class);
    ovs_mutex_unlock(&dpif_offload_mutex);

    return error;
}

static void
dpif_offload_show_classes(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    const struct shash_node **list;
    struct ds ds;

    ds_init(&ds);
    ovs_mutex_lock(&dpif_offload_mutex);

    list = shash_sort(&dpif_offload_classes);
    for (size_t i = 0; i < shash_count(&dpif_offload_classes); i++) {
        const struct dpif_offload_class *class = list[i]->data;

        if (i == 0) {
            ds_put_cstr(&ds, "Offload Class     Supported dpif class(es)\n");
            ds_put_cstr(&ds, "----------------  ------------------------\n");
        }

        ds_put_format(&ds, "%-16s  ", list[i]->name);

        for (size_t j = 0; class->supported_dpif_types[j] != NULL; j++) {
            ds_put_format(&ds, "%*s%s\n", j == 0 ? 0 : 18, "",
                          class->supported_dpif_types[j]);
        }
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    free(list);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
dp_offload_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    unixctl_command_register("dpif/offload/classes", NULL, 0, 0,
                             dpif_offload_show_classes, NULL);

    for (int i = 0; i < ARRAY_SIZE(base_dpif_offload_classes); i++) {
        ovs_assert(base_dpif_offload_classes[i]->open
                   && base_dpif_offload_classes[i]->close
                   && base_dpif_offload_classes[i]->can_offload
                   && base_dpif_offload_classes[i]->port_add
                   && base_dpif_offload_classes[i]->port_del);

        dpif_offload_register_provider(base_dpif_offload_classes[i]);
    }
    ovsthread_once_done(&once);
}

static int
dpif_offload_attach_provider_to_dpif__(struct dpif *dpif,
                                       struct dpif_offload *offload)
{
    struct dpif_offload *offload_entry = NULL;

    LIST_FOR_EACH (offload_entry, dpif_list_node, &dpif->offload_providers) {
        if (offload_entry == offload || !strcmp(offload->name,
                                                offload_entry->name)) {
            return EEXIST;
        }
    }

    ovs_list_push_back(&dpif->offload_providers, &offload->dpif_list_node);
    return 0;
}

static int
dpif_offload_attach_provider_to_dpif(struct dpif *dpif,
                                     struct dpif_offload *offload)
{
    int error;

    ovs_mutex_lock(&dpif->offload_mutex);
    error = dpif_offload_attach_provider_to_dpif__(dpif, offload);
    ovs_mutex_unlock(&dpif->offload_mutex);
    return error;
}

int
dpif_offload_attach_providers(struct dpif *dpif)
{
    struct ovs_list provider_list = OVS_LIST_INITIALIZER(&provider_list);
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif));
    struct dpif_offload *offload;
    struct shash_node *node;
    char *tokens, *saveptr;

    /* Open all the providers supporting this dpif type. */
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;
        for (size_t i = 0; class->supported_dpif_types[i] != NULL; i++) {
            if (!strcmp(class->supported_dpif_types[i], dpif_type_str)) {
                int error = class->open(class, dpif, &offload);
                if (error) {
                    VLOG_WARN("failed to initialize dpif offload provider "
                              "%s for %s: %s",
                              class->type, dpif_name(dpif),
                              ovs_strerror(error));
                } else {
                    ovs_list_push_back(&provider_list,
                                       &offload->dpif_list_node);
                }
                break;
            }
        }
    }

    ovs_mutex_lock(&dpif_offload_mutex);

    /* Attach all the providers based on the priority list. */
    tokens = xstrdup(dpif_offload_provider_priority_list);

    for (char *name = strtok_r(tokens, ",", &saveptr);
         name;
         name = strtok_r(NULL, ",", &saveptr)) {

        LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {

            if (!strcmp(name, offload->class->type)) {
                int error;

                ovs_list_remove(&offload->dpif_list_node);
                error = dpif_offload_attach_provider_to_dpif(dpif, offload);
                if (error) {
                    VLOG_WARN(
                        "failed to add dpif offload provider %s to %s: %s",
                        offload->class->type, dpif_name(dpif),
                        ovs_strerror(error));

                    offload->class->close(offload);
                }
                break;
            }
        }
    }
    free(tokens);

    /* Add remaining entries in order. */
    LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {
        int error;

        ovs_list_remove(&offload->dpif_list_node);
        error = dpif_offload_attach_provider_to_dpif(dpif, offload);
        if (error) {
            VLOG_WARN("failed to add dpif offload provider %s to %s: %s",
                      offload->class->type, dpif_name(dpif),
                      ovs_strerror(error));

            offload->class->close(offload);
        }
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    return 0;
}

void
dpif_offload_detach_providers(struct dpif *dpif)
{
    struct ovs_list destruct_list = OVS_LIST_INITIALIZER(&destruct_list);
    struct dpif_offload *offload_entry = NULL;

    /* On destruction we remove all providers in one go from the list,
     * and free/close the individual providers. */
     ovs_mutex_lock(&dpif->offload_mutex);
     ovs_list_push_back_all(&destruct_list, &dpif->offload_providers);
     ovs_mutex_unlock(&dpif->offload_mutex);

     /* We need to use the safe variant here as we removed the entry, and the
      * close API will free() it. */
     LIST_FOR_EACH_SAFE (offload_entry, dpif_list_node, &destruct_list) {
         char *name = offload_entry->name;

         ovs_list_remove(&offload_entry->dpif_list_node);
         offload_entry->class->close(offload_entry);
         ovsrcu_postpone(free, name);
     }
}

void
dpif_offload_set_config(struct dpif *dpif, const struct smap *other_cfg)
{
    struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        if (offload->class->set_config) {
            offload->class->set_config(offload, other_cfg);
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}


void
dpif_offload_init(struct dpif_offload *offload,
                  const struct dpif_offload_class *class,
                  struct dpif *dpif)
{
    ovs_assert(offload && class && dpif);

    offload->dpif = dpif;
    offload->class = class;
    offload->name = xasprintf("%s[%s]", class->type, dpif_name(dpif));
}

const char *
dpif_offload_name(const struct dpif_offload *offload)
{
    return offload->name;
}

const char *
dpif_offload_class_type(const struct dpif_offload *offload)
{
    return offload->class->type;
}

bool dpif_offload_get_debug(const struct dpif_offload *offload,
                            struct ds *ds, struct json *json)
{
    if (!offload->class->get_debug) {
        return false;
    }

    offload->class->get_debug(offload, ds, json);
    return true;
}

bool
dpif_offload_is_offload_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&dpif_offload_global_enabled, &enabled);
    return enabled;
}

bool
dpif_offload_is_offload_rebalance_policy_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&dpif_offload_rebalance_policy, &enabled);
    return enabled;
}

void dpif_offload_set_netdev_offload(struct netdev *netdev,
                                     struct dpif_offload *offload)
{
    ovsrcu_set(&netdev->dpif_offload, offload);
}

static bool
dpif_offload_try_port_add(struct dpif_offload *offload, struct netdev *netdev,
                          odp_port_t port_no)
{
    if (offload->class->can_offload(offload, netdev)) {
        int err = offload->class->port_add(offload, netdev, port_no);
        if (!err) {
            VLOG_DBG("netdev %s added to dpif-offload provider %s",
                     netdev_get_name(netdev), dpif_offload_name(offload));
            return true;
        } else {
            VLOG_ERR("Failed adding netdev %s to dpif-offload provider "
                     "%s, error %s",
                     netdev_get_name(netdev), dpif_offload_name(offload),
                     ovs_strerror(err));
        }
    } else {
        VLOG_DBG("netdev %s failed can_offload for dpif-offload provider %s",
                 netdev_get_name(netdev), dpif_offload_name(offload));
    }
    return false;
}

void dpif_offload_port_add(struct dpif *dpif, struct netdev *netdev,
                           odp_port_t port_no)
{
    struct dpif_offload *offload;

    const char *port_priority = smap_get(&port_order_cfg,
                                         netdev_get_name(netdev));

    ovs_mutex_lock(&dpif->offload_mutex);
    if (port_priority) {
        char *tokens = xstrdup(port_priority);
        char *saveptr;

        VLOG_DBG("for netdev %s using port priority %s",
                 netdev_get_name(netdev), port_priority);

        for (char *name = strtok_r(tokens, ",", &saveptr);
             name;
             name = strtok_r(NULL, ",", &saveptr)) {
            bool provider_added = false;

            if (!strcmp("none", name)) {
                break;
            }

            LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
                if (!strcmp(name, offload->class->type)) {

                    provider_added = dpif_offload_try_port_add(offload, netdev,
                                                               port_no);
                    break;
                }
            }

            if (provider_added) {
                break;
            }
        }
        free(tokens);
    } else {
        LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
            if (dpif_offload_try_port_add(offload, netdev, port_no)) {
                break;
            }
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}

void dpif_offload_port_del(struct dpif *dpif, odp_port_t port_no) {
    struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        int err = offload->class->port_del(offload, port_no);
        if (err) {
            VLOG_ERR("Failed deleting port_no %d from dpif-offload provider "
                     "%s, error %s", port_no, dpif_offload_name(offload),
                     ovs_strerror(err));
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}

void dpif_offload_port_set_config(struct dpif *dpif, odp_port_t port_no,
                                  const struct smap *cfg)
{
    struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        if (offload->class->port_set_config) {
            offload->class->port_set_config(offload, port_no, cfg);
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}

void
dpif_offload_set_global_cfg(const struct ovsrec_open_vswitch *cfg)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    const struct smap *other_cfg = &cfg->other_config;
    const char *priority;

    /* The 'hw-offload-priority' parameter can only be set at startup,
     * any successive change needs a restart. */
    priority = smap_get(other_cfg, "hw-offload-priority");

    if (ovsthread_once_start(&init_once)) {
        /* Initialize the dpif-offload layer in case it's not yet initialized
         * at the first invocation of setting the configuration. */
        dp_offload_initialize();

        /* If priority is not set keep the default value. */
        if (priority) {
            char *tokens = xstrdup(priority);
            char *saveptr;

            dpif_offload_provider_priority_list = xstrdup(priority);

            /* Log a warning for unknown offload providers. */
            for (char *name = strtok_r(tokens, ",", &saveptr);
                 name;
                 name = strtok_r(NULL, ",", &saveptr)) {

                if (!shash_find(&dpif_offload_classes, name)) {
                    VLOG_WARN("'hw-offload-priority' configuration has an "
                              "unknown type; %s", name);
                }
            }
            free(tokens);
        }
        ovsthread_once_done(&init_once);
    } else {
        if (priority && strcmp(priority,
                               dpif_offload_provider_priority_list)) {
            VLOG_INFO_ONCE("'hw-offload-priority' configuration changed; "
                           "restart required");
        }
    }

    /* Handle other global configuration settings.
     *
     * According to the manual the 'hw-offload' parameter requires a restart
     * when changed.  In practice this is only needed on disable, as it will
     * not actually disable hw-offload when requested. */
     if (smap_get_bool(other_cfg, "hw-offload", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            atomic_store_relaxed(&dpif_offload_global_enabled, true);
            VLOG_INFO("hw-offload API Enabled");

            if (smap_get_bool(other_cfg, "offload-rebalance", false)) {
                atomic_store_relaxed(&dpif_offload_rebalance_policy, true);
            }

            ovsthread_once_done(&once_enable);
        }
    }

    /* Filter out the 'hw-offload-priority' per port setting we need in before
     * ports are added, so we can assign the correct offload-provider.
     * Note that we can safely rebuild the map here, as we only access this
     * from the same (main) thread. */
    smap_clear(&port_order_cfg);
    for (int i = 0; i < cfg->n_bridges; i++) {
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];

        for (int j = 0; j < br_cfg->n_ports; j++) {
            const struct ovsrec_port *port_cfg = br_cfg->ports[j];

            priority = smap_get(&port_cfg->other_config,
                                "hw-offload-priority");
            if (priority) {
                smap_add(&port_order_cfg, port_cfg->name, priority);
            }
        }
    }
}

void
dpif_offload_flow_flush(struct dpif *dpif)
{
    const struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        if (offload->class->flow_flush) {
            int err = offload->class->flow_flush(offload);
            if (err) {
                VLOG_ERR("Failed flow flush on dpif-offload provider "
                    "%s, error %s", dpif_offload_name(offload),
                    ovs_strerror(err));
            }
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}

void
dpif_offload_meter_set(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_config *config)
{
    const struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        if (offload->class->meter_set) {
            int err = offload->class->meter_set(offload, meter_id, config);
            if (err) {
                /* Offload APIs could fail, for example, because the offload
                 * is not supported. This is fine, as the offload API should
                 * take care of this. */
                VLOG_DBG_RL(&rl_dbg,
                            "Failed setting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}

void
dpif_offload_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats)
{
    const struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        if (offload->class->meter_get) {
            int err = offload->class->meter_get(offload, meter_id, stats);
            if (err) {
                VLOG_DBG_RL(&rl_dbg,
                            "Failed getting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}

void
dpif_offload_meter_del(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats)
{
    const struct dpif_offload *offload;

    ovs_mutex_lock(&dpif->offload_mutex);
    LIST_FOR_EACH (offload, dpif_list_node, &dpif->offload_providers) {
        if (offload->class->meter_del) {
            int err = offload->class->meter_del(offload, meter_id, stats);
            if (err) {
                VLOG_DBG_RL(&rl_dbg,
                            "Failed deleting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
    ovs_mutex_unlock(&dpif->offload_mutex);
}


int
dpif_offload_netdev_flush_flows(struct netdev *netdev)
{
    const struct dpif_offload *offload;

    offload = ovsrcu_get(const struct dpif_offload *, &netdev->dpif_offload);

    if (offload && offload->class->netdev_flow_flush) {
        return offload->class->netdev_flow_flush(offload, netdev);
    }
    return EOPNOTSUPP;
}


struct dpif_offload_port_mgr *
dpif_offload_port_mgr_init(void)
{
    struct dpif_offload_port_mgr *mgr = xmalloc(sizeof *mgr);

    ovs_mutex_init(&mgr->cmap_mod_lock);

    cmap_init(&mgr->odp_port_to_port);
    cmap_init(&mgr->netdev_to_port);
    cmap_init(&mgr->ifindex_to_port);

    return mgr;
}

void dpif_offload_port_mgr_uninit(struct dpif_offload_port_mgr *mgr)
{
    if (!mgr) {
        return;
    }

    ovs_assert(cmap_count(&mgr->odp_port_to_port) == 0);
    ovs_assert(cmap_count(&mgr->netdev_to_port) == 0);
    ovs_assert(cmap_count(&mgr->ifindex_to_port) == 0);

    cmap_destroy(&mgr->odp_port_to_port);
    cmap_destroy(&mgr->netdev_to_port);
    cmap_destroy(&mgr->ifindex_to_port);
    free(mgr);
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_ifindex(struct dpif_offload_port_mgr *mgr,
                                      int ifindex)
{
    struct dpif_offload_port_mgr_port *port;

    if (ifindex < 0) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (port, ifindex_node, hash_int(ifindex, 0),
                             &mgr->ifindex_to_port)
    {
        if (port->ifindex == ifindex) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_netdev(struct dpif_offload_port_mgr *mgr,
                                     struct netdev *netdev)
{
    struct dpif_offload_port_mgr_port *port;

    if (!netdev) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (port, netdev_node, hash_pointer(netdev, 0),
                             &mgr->netdev_to_port)
    {
        if (port->netdev == netdev) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_odp_port(struct dpif_offload_port_mgr *mgr,
                                       odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port;

    CMAP_FOR_EACH_WITH_HASH (port, odp_port_node,
                             hash_int(odp_to_u32(port_no), 0),
                             &mgr->odp_port_to_port)
    {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_remove(struct dpif_offload_port_mgr *mgr,
                             odp_port_t port_no, bool keep_netdev_ref)
{
    struct dpif_offload_port_mgr_port *port;

    ovs_mutex_lock(&mgr->cmap_mod_lock);

    port = dpif_offload_port_mgr_find_by_odp_port(mgr, port_no);

    if (port) {
        cmap_remove(&mgr->odp_port_to_port, &port->odp_port_node,
                    hash_int(odp_to_u32(port_no), 0));
        cmap_remove(&mgr->netdev_to_port, &port->netdev_node,
                    hash_pointer(port->netdev, 0));

        if (port->ifindex >= 0) {
            cmap_remove(&mgr->ifindex_to_port, &port->ifindex_node,
                        hash_int(port->ifindex, 0));
        }
        if (!keep_netdev_ref) {
            netdev_close(port->netdev);
        }
    }

    ovs_mutex_unlock(&mgr->cmap_mod_lock);
    return port;
}

bool
dpif_offload_port_mgr_add(struct dpif_offload_port_mgr *mgr,
                          struct dpif_offload_port_mgr_port *port,
                          struct netdev *netdev, odp_port_t port_no,
                          bool need_ifindex)
{
    ovs_assert(netdev);

    memset(port, 0, sizeof *port);
    port->netdev = netdev_ref(netdev);
    port->port_no = port_no;
    port->ifindex = need_ifindex ? netdev_get_ifindex(netdev) : -1;

    ovs_mutex_lock(&mgr->cmap_mod_lock);

    if (dpif_offload_port_mgr_find_by_odp_port(mgr, port_no)
        || dpif_offload_port_mgr_find_by_ifindex(mgr, port->ifindex)
        || dpif_offload_port_mgr_find_by_netdev(mgr, port->netdev)) {

        ovs_mutex_unlock(&mgr->cmap_mod_lock);
        return false;
    }

    cmap_insert(&mgr->odp_port_to_port, &port->odp_port_node,
                hash_int(odp_to_u32(port_no), 0));

    cmap_insert(&mgr->netdev_to_port, &port->netdev_node,
                hash_pointer(netdev, 0));

    if (port->ifindex >= 0) {
        cmap_insert(&mgr->ifindex_to_port, &port->ifindex_node,
                    hash_int(port->ifindex, 0));
    }

    ovs_mutex_unlock(&mgr->cmap_mod_lock);
    return true;
}

void dpif_offload_port_mgr_traverse_ports(
    struct dpif_offload_port_mgr *mgr,
    bool (*cb)(struct dpif_offload_port_mgr_port *, void *),
    void *aux)
{
    struct dpif_offload_port_mgr_port *port;

    CMAP_FOR_EACH (port, odp_port_node, &mgr->odp_port_to_port) {
        if (cb(port, aux)) {
            break;
        }
    }
}
