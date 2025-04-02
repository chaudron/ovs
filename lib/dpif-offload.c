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
#include "unixctl.h"
#include "util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload);

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
                   && base_dpif_offload_classes[i]->close);

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

void
dpif_offload_set_global_cfg(const struct smap *other_cfg)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    const char *priority = smap_get(other_cfg, "hw-offload-priority");

    /* The 'hw-offload-priority' parameter can only be set at startup,
     * any successive change needs a restart. */
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
}
