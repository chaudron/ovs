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
static struct shash dpif_offload_providers \
    OVS_GUARDED_BY(dpif_offload_mutex) = \
    SHASH_INITIALIZER(&dpif_offload_providers);

static const struct dpif_offload_class *base_dpif_offload_classes[] = {
#if defined(__linux__)
    &dpif_offload_tc_class,
#endif
#ifdef DPDK_NETDEV
    &dpif_offload_dpdk_class,
#endif
    /* If you add an offload class to this structure, make sure you also
     * update the dpif_offload_provider_priority_list below. */
    &dpif_offload_dummy_class,
    &dpif_offload_dummy_x_class,
};

static char *dpif_offload_provider_priority_list = "tc,dpdk,dummy,dummy_x";
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

static struct dp_offload*
dpif_offload_get_dp_offload(const struct dpif *dpif)
{
    return ovsrcu_get(struct dp_offload *, &dpif->dp_offload);
}

static int
dpif_offload_attach_provider_to_dp_offload__(struct dp_offload *dp_offload,
                                             struct dpif_offload *offload)
{
    struct ovs_list *providers_list = &dp_offload->offload_providers;
    struct dpif_offload *offload_entry;

    LIST_FOR_EACH (offload_entry, dpif_list_node, providers_list) {
        if (offload_entry == offload || !strcmp(offload->name,
                                                offload_entry->name)) {
            return EEXIST;
        }
    }

    ovs_list_push_back(providers_list, &offload->dpif_list_node);
    return 0;
}

static int
dpif_offload_attach_provider_to_dp_offload(struct dp_offload *dp_offload,
                                           struct dpif_offload *offload)
{
    int error;

    ovs_assert(dp_offload);

    error = dpif_offload_attach_provider_to_dp_offload__(dp_offload, offload);
    return error;
}

static int
dpif_offload_attach_dp_offload(struct dpif *dpif,
                               struct dp_offload *dp_offload)
    OVS_REQUIRES(dpif_offload_mutex)
{
    ovsrcu_set(&dpif->dp_offload, dp_offload);
    ovs_refcount_ref(&dp_offload->ref_cnt);
    return 0;
}

static int
dpif_offload_attach_providers_(struct dpif *dpif)
    OVS_REQUIRES(dpif_offload_mutex)
{
    struct ovs_list provider_list = OVS_LIST_INITIALIZER(&provider_list);
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif));
    struct dp_offload *dp_offload;
    struct dpif_offload *offload;
    struct shash_node *node;
    char *tokens, *saveptr;

    /* Allocate and attach dp_offload to dpif. */
    dp_offload = xmalloc(sizeof *dp_offload);
    dp_offload->dpif_name = xstrdup(dpif_name(dpif));
    ovs_mutex_init_recursive(&dp_offload->offload_mutex);
    ovs_refcount_init(&dp_offload->ref_cnt);
    ovs_list_init(&dp_offload->offload_providers);
    shash_add(&dpif_offload_providers, dp_offload->dpif_name, dp_offload);

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

    /* Attach all the providers based on the priority list. */
    tokens = xstrdup(dpif_offload_provider_priority_list);

    for (char *name = strtok_r(tokens, ",", &saveptr);
         name;
         name = strtok_r(NULL, ",", &saveptr)) {

        LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {

            if (!strcmp(name, offload->class->type)) {
                int error;

                ovs_list_remove(&offload->dpif_list_node);
                error = dpif_offload_attach_provider_to_dp_offload(dp_offload,
                                                                   offload);
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
        error = dpif_offload_attach_provider_to_dp_offload(dp_offload,
                                                           offload);
        if (error) {
            VLOG_WARN("failed to add dpif offload provider %s to %s: %s",
                      offload->class->type, dpif_name(dpif),
                      ovs_strerror(error));

            offload->class->close(offload);
        }
    }

    /* Attach dp_offload to dpif. */
    ovsrcu_set(&dpif->dp_offload, dp_offload);

    return 0;
}

int
dpif_offload_attach_providers(struct dpif *dpif)
{
    struct dp_offload *dp_offload;
    int rc;

    ovs_mutex_lock(&dpif_offload_mutex);

    dp_offload = shash_find_data(&dpif_offload_providers, dpif_name(dpif));
    if (dp_offload) {
        rc = dpif_offload_attach_dp_offload(dpif, dp_offload);
    } else {
        rc = dpif_offload_attach_providers_(dpif);
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    return rc;
}

static void
dpif_offload_free_dp_offload_rcu(struct dp_offload *dp_offload)
{
    struct dpif_offload *offload_entry;

    /* We need to use the safe variant here as we removed the entry, and the
     * close API will free() it. */
    LIST_FOR_EACH_SAFE (offload_entry, dpif_list_node,
                        &dp_offload->offload_providers)
    {
        char *name = offload_entry->name;

        ovs_list_remove(&offload_entry->dpif_list_node);
        offload_entry->class->close(offload_entry);
        ovsrcu_postpone(free, name);
    }

    /* Free remaining resources. */
    ovs_mutex_destroy(&dp_offload->offload_mutex);
    free(dp_offload->dpif_name);
    free(dp_offload);
}

void
dpif_offload_detach_providers(struct dpif *dpif)
{
    struct dp_offload *dp_offload = dpif_offload_get_dp_offload(dpif);

    if (dp_offload) {
        /* Take dpif_offload_mutex so that, if dp_offload->ref_cnt falls to
         * zero, we can't get a new reference to 'dp_offload' through the
         * 'dpif_offload_providers' shash. */
        ovs_mutex_lock(&dpif_offload_mutex);
        if (ovs_refcount_unref_relaxed(&dp_offload->ref_cnt) == 1) {
            shash_find_and_delete(&dpif_offload_providers,
                                  dp_offload->dpif_name);
            ovsrcu_postpone(dpif_offload_free_dp_offload_rcu, dp_offload);
        }
         ovs_mutex_unlock(&dpif_offload_mutex);
         ovsrcu_set(&dpif->dp_offload, NULL);
    }
}


void
dpif_offload_init(struct dpif_offload *offload,
                  const struct dpif_offload_class *class,
                  struct dpif *dpif)
{
    ovs_assert(offload && class && dpif);

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
dpif_offload_dump_start(struct dpif_offload_dump *dump,
                        const struct dpif *dpif)
{
    memset(dump, 0, sizeof *dump);
    dump->dpif = dpif;
}

bool
dpif_offload_dump_next(struct dpif_offload_dump *dump,
                       struct dpif_offload **offload)
{
    struct dp_offload *dp_offload;

    if (!offload || !dump || dump->error) {
        return false;
    }

    dp_offload = dpif_offload_get_dp_offload(dump->dpif);
    if (!dp_offload) {
        return false;
    }

    if (dump->state) {
        /* In theory, list entries should not be removed. However, in case
         * someone calls this during destruction and the node has disappeared,
         * we will return EIDRM (Identifier removed). */
        struct dpif_offload *offload_entry = NULL;

        LIST_FOR_EACH (offload_entry, dpif_list_node,
                       &dp_offload->offload_providers) {
            if (offload_entry == dump->state) {
                if (ovs_list_back(&dp_offload->offload_providers)
                    == &offload_entry->dpif_list_node) {
                        dump->error = EOF;
                } else {
                    *offload = CONTAINER_OF(
                        offload_entry->dpif_list_node.next,
                        struct dpif_offload, dpif_list_node);

                    dump->state = *offload;
                }
                break;
            }
        }

        if (!offload_entry) {
            dump->error = EIDRM;
        }
    } else {
        /* Get the first entry in the list. */
        if (!ovs_list_is_empty(&dp_offload->offload_providers)) {
            *offload = CONTAINER_OF(
                ovs_list_front(&dp_offload->offload_providers),
                struct dpif_offload, dpif_list_node);

            dump->state = *offload;
        } else {
            dump->error = EOF;
        }
    }

    return !dump->error;
}

int
dpif_offload_dump_done(struct dpif_offload_dump *dump)
{
    return dump->error == EOF ? 0 : dump->error;
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

            if (smap_get_bool(other_cfg, "offload-rebalance", false)) {
                atomic_store_relaxed(&dpif_offload_rebalance_policy, true);
            }

            ovsthread_once_done(&once_enable);
        }
    }
}
