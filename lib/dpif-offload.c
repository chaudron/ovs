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
    &dpif_offload_dummy_class,
};

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
    unixctl_command_register("dpif/offload/classes", NULL, 0, 0,
                             dpif_offload_show_classes, NULL);

    for (int i = 0; i < ARRAY_SIZE(base_dpif_offload_classes); i++) {
        ovs_assert(base_dpif_offload_classes[i]->open
                   && base_dpif_offload_classes[i]->close);

        dpif_offload_register_provider(base_dpif_offload_classes[i]);
    }
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
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif));
    struct shash_node *node;

    ovs_mutex_lock(&dpif_offload_mutex);

    /* Attach all the providers supporting this dpif type. */
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;
        for (size_t i = 0; class->supported_dpif_types[i] != NULL; i++) {
            if (!strcmp(class->supported_dpif_types[i], dpif_type_str)) {
                struct dpif_offload *offload;
                int error;

                error = class->open(class, dpif, &offload);
                if (!error) {

                    error = dpif_offload_attach_provider_to_dpif(dpif,
                                                                 offload);
                    if (error) {
                        VLOG_WARN("failed to add dpif offload provider "
                                  "%s to %s: %s",
                                  class->type, dpif_name(dpif),
                                  ovs_strerror(error));
                        class->close(offload);
                    }
                } else {
                    VLOG_WARN("failed to initialize dpif offload provider "
                              "%s for %s: %s",
                              class->type, dpif_name(dpif),
                              ovs_strerror(error));
                }
               break;
            }
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
