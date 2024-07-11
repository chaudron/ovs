/*
 * Copyright (c) 2024 Red Hat, Inc.
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
#include "ofproto-dpif-lsample.h"

#include "cmap.h"
#include "dpif.h"
#include "hash.h"
#include "ofproto.h"
#include "ofproto-dpif.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/thread.h"
#include "unixctl.h"

/* Dpif local sampling.
 *
 * Thread safety: dpif_lsample allows lockless concurrent reads of local
 * sampling exporters as long as the following restrictions are met:
 *   1) While the last reference is being dropped, i.e: a thread is calling
 *      "dpif_lsample_unref" on the last reference, other threads cannot call
 *      "dpif_lsample_ref".
 *   2) Threads do not quiese while holding references to internal
 *      lsample_exporter objects.
 */

struct dpif_lsample {
    struct cmap exporters;          /* Contains lsample_exporter_node instances
                                     * indexed by collector_set_id. */
    struct ovs_mutex mutex;         /* Protects concurrent insertion/deletion
                                     * of exporters. */

    struct ovs_refcount ref_cnt;    /* Controls references to this instance. */
};

struct lsample_exporter {
    struct ofproto_lsample_options options;
    atomic_uint64_t n_packets;
    atomic_uint64_t n_bytes;
};

struct lsample_exporter_node {
    struct cmap_node node;              /* In dpif_lsample->exporters. */
    struct lsample_exporter exporter;
};

static void
dpif_lsample_delete_exporter(struct dpif_lsample *lsample,
                             struct lsample_exporter_node *node)
{
    ovs_mutex_lock(&lsample->mutex);
    cmap_remove(&lsample->exporters, &node->node,
                hash_int(node->exporter.options.collector_set_id, 0));
    ovs_mutex_unlock(&lsample->mutex);

    ovsrcu_postpone(free, node);
}

/* Adds an exporter with the provided options which are copied. */
static struct lsample_exporter_node *
dpif_lsample_add_exporter(struct dpif_lsample *lsample,
                          const struct ofproto_lsample_options *options)
{
    struct lsample_exporter_node *node;

    node = xzalloc(sizeof *node);
    node->exporter.options = *options;

    ovs_mutex_lock(&lsample->mutex);
    cmap_insert(&lsample->exporters, &node->node,
                hash_int(options->collector_set_id, 0));
    ovs_mutex_unlock(&lsample->mutex);

    return node;
}

static struct lsample_exporter_node *
dpif_lsample_find_exporter_node(const struct dpif_lsample *lsample,
                                const uint32_t collector_set_id)
{
    struct lsample_exporter_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, node,
                            hash_int(collector_set_id, 0),
                            &lsample->exporters) {
        if (node->exporter.options.collector_set_id == collector_set_id) {
            return node;
        }
    }
    return NULL;
}

/* Sets the lsample configuration and returns true if the configuration
 * has changed. */
bool
dpif_lsample_set_options(struct dpif_lsample *lsample,
                         const struct ofproto_lsample_options *options,
                         size_t n_options)
{
    const struct ofproto_lsample_options *opt;
    struct lsample_exporter_node *node;
    bool changed = false;
    int i;

    for (i = 0; i < n_options; i++) {
        opt = &options[i];
        node = dpif_lsample_find_exporter_node(lsample,
                                               opt->collector_set_id);
        if (!node) {
            dpif_lsample_add_exporter(lsample, opt);
            changed = true;
        } else if (memcmp(&node->exporter.options, opt, sizeof(*opt))) {
            dpif_lsample_delete_exporter(lsample, node);
            dpif_lsample_add_exporter(lsample, opt);
            changed = true;
        }
    }

    /* Delete exporters that have been removed. */
    CMAP_FOR_EACH (node, node, &lsample->exporters) {
        for (i = 0; i < n_options; i++) {
            if (node->exporter.options.collector_set_id
                == options[i].collector_set_id) {
                break;
            }
        }
        if (i == n_options) {
            dpif_lsample_delete_exporter(lsample, node);
            changed = true;
        }
    }

    return changed;
}

/* Returns the group_id for a given collector_set_id, if it exists. */
bool
dpif_lsample_get_group_id(struct dpif_lsample *ps, uint32_t collector_set_id,
                          uint32_t *group_id)
{
    struct lsample_exporter_node *node;
    bool found = false;

    node = dpif_lsample_find_exporter_node(ps, collector_set_id);
    if (node) {
        found = true;
        *group_id = node->exporter.options.group_id;
    }
    return found;
}

void
dpif_lsample_credit_stats(struct dpif_lsample *lsample,
                          uint32_t collector_set_id,
                          const struct dpif_flow_stats *stats)
{
    struct lsample_exporter_node *node;
    uint64_t orig;

    node = dpif_lsample_find_exporter_node(lsample, collector_set_id);
    if (node) {
        atomic_add_relaxed(&node->exporter.n_packets, stats->n_packets, &orig);
        atomic_add_relaxed(&node->exporter.n_bytes, stats->n_bytes, &orig);
    }
}

struct dpif_lsample *
dpif_lsample_create(void)
{
    struct dpif_lsample *lsample;

    lsample = xzalloc(sizeof *lsample);
    cmap_init(&lsample->exporters);
    ovs_mutex_init(&lsample->mutex);
    ovs_refcount_init(&lsample->ref_cnt);

    return lsample;
}

static void
dpif_lsample_destroy(struct dpif_lsample *lsample)
{
    if (lsample) {
        struct lsample_exporter_node *node;

        CMAP_FOR_EACH (node, node, &lsample->exporters) {
            dpif_lsample_delete_exporter(lsample, node);
        }
        cmap_destroy(&lsample->exporters);
        free(lsample);
    }
}

struct dpif_lsample *
dpif_lsample_ref(const struct dpif_lsample *lsample_)
{
    struct dpif_lsample *lsample = CONST_CAST(struct dpif_lsample *, lsample_);

    if (lsample) {
        ovs_refcount_ref(&lsample->ref_cnt);
    }
    return lsample;
}

void
dpif_lsample_unref(struct dpif_lsample *lsample)
{
    if (lsample && ovs_refcount_unref_relaxed(&lsample->ref_cnt) == 1) {
        dpif_lsample_destroy(lsample);
    }
}

static int
comp_exporter_collector_id(const void *a_, const void *b_)
{
    const struct lsample_exporter_node *a, *b;

    a = *(struct lsample_exporter_node **) a_;
    b = *(struct lsample_exporter_node **) b_;

    if (a->exporter.options.collector_set_id >
        b->exporter.options.collector_set_id) {
        return 1;
    }
    if (a->exporter.options.collector_set_id <
        b->exporter.options.collector_set_id) {
        return -1;
    }
    return 0;
}

static void
lsample_exporter_list(struct dpif_lsample *lsample,
                      struct lsample_exporter_node ***list,
                      size_t *num_exporters)
{
    struct lsample_exporter_node **exporter_list;
    struct lsample_exporter_node *node;
    size_t k = 0, n;

    n = cmap_count(&lsample->exporters);

    exporter_list = xcalloc(n, sizeof *exporter_list);

    CMAP_FOR_EACH (node, node, &lsample->exporters) {
        if (k >= n) {
            break;
        }
        exporter_list[k++] = node;
    }

    qsort(exporter_list, k, sizeof *exporter_list, comp_exporter_collector_id);

    *list = exporter_list;
    *num_exporters = k;
}

static void
lsample_unixctl_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct lsample_exporter_node **node_list = NULL;
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct ofproto_dpif *ofproto;
    size_t i, num;

    ofproto = ofproto_dpif_lookup_by_name(argv[1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    if (!ofproto->lsample) {
        unixctl_command_reply_error(conn,
                                    "no local sampling exporters configured");
        return;
    }

    ds_put_format(&ds, "Local sample statistics for bridge \"%s\":\n",
                  argv[1]);

    lsample_exporter_list(ofproto->lsample, &node_list, &num);

    for (i = 0; i < num; i++) {
        uint64_t n_bytes;
        uint64_t n_packets;

        struct lsample_exporter_node *node = node_list[i];

        atomic_read_relaxed(&node->exporter.n_packets, &n_packets);
        atomic_read_relaxed(&node->exporter.n_bytes, &n_bytes);

        if (i) {
            ds_put_cstr(&ds, "\n");
        }

        ds_put_format(&ds, "Collector Set ID: %"PRIu32":\n",
                    node->exporter.options.collector_set_id);
        ds_put_format(&ds, "  Group ID     : %"PRIu32"\n",
                    node->exporter.options.group_id);
        ds_put_format(&ds, "  Total packets: %"PRIu64"\n", n_packets);
        ds_put_format(&ds, "  Total bytes  : %"PRIu64"\n", n_bytes);
    }

    free(node_list);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void dpif_lsample_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        unixctl_command_register("lsample/show", "bridge", 1, 1,
                                 lsample_unixctl_show, NULL);
        ovsthread_once_done(&once);
    }
}
