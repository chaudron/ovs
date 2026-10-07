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
#include <errno.h>

#include <rte_pci.h>

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dpif-offload-doca-private.h"
#include "mov-avg.h"
#include "mpsc-queue.h"
#include "netdev-doca.h"
#include "netdev-provider.h"
#include "ovs-doca.h"
#include "ovs-rcu.h"
#include "util.h"
#include "uuid.h"

#include "openvswitch/json.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_doca);

#define DEFAULT_OFFLOAD_THREAD_COUNT 1
#define MAX_OFFLOAD_THREAD_COUNT (OVS_DOCA_MAX_STEERING_QUEUES - 1)

enum doca_offload_type {
    DOCA_OFFLOAD_FLOW,
    DOCA_OFFLOAD_FLUSH,
};

enum {
    DOCA_NETDEV_FLOW_OFFLOAD_OP_PUT,
    DOCA_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

struct doca_offload_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        atomic_uint64_t enqueued_item;
        struct mov_avg_cma cma;
        struct mov_avg_ema ema;
        struct doca_offload *offload;
        pthread_t thread;
    );
};

struct doca_offload_flow_item {
    int op;
    odp_port_t in_port;
    ovs_u128 ufid;
    unsigned pmd_id;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;
    odp_port_t orig_in_port; /* Originating in_port for tunnel flows. */
    bool requested_stats;
    void *flow_reference;
    struct dpif_offload_flow_cb_data callback;
};

struct doca_offload_flush_item {
    struct netdev *netdev;
    struct doca_offload *offload;
    struct ovs_barrier *barrier;
};

union doca_offload_thread_data {
    struct doca_offload_flow_item flow;
    struct doca_offload_flush_item flush;
};

struct doca_offload_thread_item {
    struct mpsc_queue_node node;
    enum doca_offload_type type;
    long long int timestamp;
    union doca_offload_thread_data data[0];
};

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

static struct doca_offload *
doca_offload_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_doca_class);
    return CONTAINER_OF(offload, struct doca_offload, offload);
}

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

static unsigned int
doca_ufid_to_thread_id(struct doca_offload *offload, const ovs_u128 ufid)
{
    uint32_t ufid_hash;

    if (offload->offload_thread_count == 1) {
        return 1;
    }

    ufid_hash = hash_words64_inline(
            (const uint64_t [2]){ ufid.u64.lo,
                                  ufid.u64.hi }, 2, 1);
    return 1 + (ufid_hash % offload->offload_thread_count);
}

static bool
doca_is_offloading_netdev(struct doca_offload *offload, struct netdev *netdev)
{
    const struct dpif_offload *netdev_offload;

    netdev_offload = ovsrcu_get(const struct dpif_offload *,
                                &netdev->dpif_offload);

    return netdev_offload == &offload->offload;
}

static struct doca_offload_thread_item *
doca_alloc_flow_offload(int op)
{
    struct doca_offload_thread_item *item;
    struct doca_offload_flow_item *flow_offload;

    item = xzalloc(sizeof *item + sizeof *flow_offload);
    flow_offload = &item->data->flow;

    item->type = DOCA_OFFLOAD_FLOW;
    flow_offload->op = op;

    return item;
}

static void
doca_free_flow_offload__(struct doca_offload_thread_item *offload)
{
    struct doca_offload_flow_item *flow_offload = &offload->data->flow;

    free(flow_offload->actions);
    free(offload);
}

static void
doca_free_flow_offload(struct doca_offload_thread_item *offload)
{
    ovsrcu_postpone(doca_free_flow_offload__, offload);
}

static void
doca_free_offload(struct doca_offload_thread_item *offload)
{
    switch (offload->type) {
    case DOCA_OFFLOAD_FLOW:
        doca_free_flow_offload(offload);
        break;
    case DOCA_OFFLOAD_FLUSH:
        free(offload);
        break;
    default:
        OVS_NOT_REACHED();
    };
}

static void
doca_append_offload(const struct doca_offload *offload,
                    struct doca_offload_thread_item *item, unsigned int tid)
{
    ovs_assert(offload->offload_threads);

    mpsc_queue_insert(&offload->offload_threads[tid].queue, &item->node);
    atomic_count_inc64(&offload->offload_threads[tid].enqueued_item);
}

static void
doca_offload_flow_enqueue(struct doca_offload *offload,
                          struct doca_offload_thread_item *item)
{
    struct doca_offload_flow_item *flow_offload = &item->data->flow;
    unsigned int tid;

    ovs_assert(item->type == DOCA_OFFLOAD_FLOW);

    tid = doca_ufid_to_thread_id(offload, flow_offload->ufid);
    doca_append_offload(offload, item, tid);
}

static int
doca_offload_del(struct doca_offload_thread *thread,
                 struct doca_offload_thread_item *item)
{
    struct doca_offload_flow_item *flow = &item->data->flow;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    int error;

    netdev = doca_offload_get_netdev(thread->offload, flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    /* Note that we are responsible for tracking offloads per PMD.  We pass
     * the delete request directly to the doca netdev offload code, which
     * will handle the actual hardware offloaded flow.  It will only remove it
     * when no other PMD needs it. */
    error = doca_netdev_flow_del(thread->offload, netdev, flow->pmd_id,
                                 &flow->ufid, flow->flow_reference,
                                 flow->requested_stats ? &stats : NULL);

do_callback:
    dpif_offload_datapath_flow_op_continue(&flow->callback,
                                           flow->requested_stats ? &stats
                                                                 : NULL,
                                           flow->pmd_id, flow->flow_reference,
                                           NULL,
                                           error);
    return error;
}

static int
doca_offload_put(struct doca_offload_thread *thread,
                 struct doca_offload_thread_item *item)
{
    struct doca_offload_flow_item *flow = &item->data->flow;
    void *previous_flow_reference = NULL;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    int error;

    netdev = doca_offload_get_netdev(thread->offload, flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    if (!doca_is_offloading_netdev(thread->offload, netdev)) {
        error = EUNATCH;
        goto do_callback;
    }

    /* Note that we are responsible for tracking offloads per PMD.  We pass
     * the put request directly to the doca netdev offload code, which
     * will handle the actual hardware offloaded flow.  It will only add it
     * when no other PMD have it offloaded. */
    error = doca_netdev_flow_put(thread->offload, flow->pmd_id,
                                 flow->flow_reference, netdev, &flow->match,
                                 CONST_CAST(struct nlattr *, flow->actions),
                                 flow->actions_len, &flow->ufid,
                                 flow->orig_in_port, &previous_flow_reference,
                                 flow->requested_stats ? &stats : NULL);
do_callback:
    dpif_offload_datapath_flow_op_continue(&flow->callback,
                                           flow->requested_stats ? &stats
                                                                 : NULL,
                                           flow->pmd_id, flow->flow_reference,
                                           previous_flow_reference,
                                           error);
    return error;
}

static void
doca_offload_flow(struct doca_offload_thread *thread,
                  struct doca_offload_thread_item *item)
{
    struct doca_offload_flow_item *flow_offload = &item->data->flow;
    const char *op;
    int ret;

    switch (flow_offload->op) {
    case DOCA_NETDEV_FLOW_OFFLOAD_OP_PUT:
        op = "put";
        ret = doca_offload_put(thread, item);
        break;
    case DOCA_NETDEV_FLOW_OFFLOAD_OP_DEL:
        op = "delete";
        ret = doca_offload_del(thread, item);
        break;
    default:
        OVS_NOT_REACHED();
    }

    VLOG_DBG("%s to %s netdev flow "UUID_FMT,
             ret == 0 ? "succeed" : "failed", op,
             UUID_ARGS((struct uuid *) &flow_offload->ufid));
}

static void
doca_offload_flush_item(struct doca_offload_thread_item *item)
{
    struct doca_offload_flush_item *flush = &item->data->flush;

    doca_netdev_flow_flush(flush->offload, flush->netdev);
    ovs_barrier_block(flush->barrier);
}

#define DOCA_OFFLOAD_BACKOFF_MIN 1
#define DOCA_OFFLOAD_BACKOFF_MAX 64
#define DOCA_OFFLOAD_QUIESCE_INTERVAL_US (10 * 1000) /* 10 ms */

static void *
doca_offload_thread_main(void *arg)
{
    struct doca_offload_thread *ofl_thread = arg;
    struct doca_offload_thread_item *offload;
    struct mpsc_queue_node *node;
    struct mpsc_queue *queue;
    long long int latency_us;
    long long int next_rcu;
    uint64_t backoff;
    bool exiting;

    if (*doca_offload_thread_id_get() == OVSTHREAD_ID_UNSET) {
        unsigned int id;

        id = atomic_count_inc(&ofl_thread->offload->next_offload_thread_id);

        /* Panic if any offload thread is getting a spurious ID. */
        ovs_assert(id < ofl_thread->offload->offload_thread_count);

        /* Thread 0 is reserved for the main thread. */
        *doca_offload_thread_id_get() = id + 1;
    }

    queue = &ofl_thread->queue;
    mpsc_queue_acquire(queue);

    do {
        long long int now;

        backoff = DOCA_OFFLOAD_BACKOFF_MIN;
        while (mpsc_queue_tail(queue) == NULL) {
            xnanosleep(backoff * 1E6);
            if (backoff < DOCA_OFFLOAD_BACKOFF_MAX) {
                backoff <<= 1;
            }

            atomic_read_relaxed(&ofl_thread->offload->offload_thread_shutdown,
                                &exiting);
            if (exiting) {
                goto exit_thread;
            }
        }

        now = time_usec();
        next_rcu = now + DOCA_OFFLOAD_QUIESCE_INTERVAL_US;
        MPSC_QUEUE_FOR_EACH_POP (node, queue) {
            offload = CONTAINER_OF(node, struct doca_offload_thread_item,
                                   node);
            atomic_count_dec64(&ofl_thread->enqueued_item);

            switch (offload->type) {
            case DOCA_OFFLOAD_FLOW:
                doca_offload_flow(ofl_thread, offload);
                break;
            case DOCA_OFFLOAD_FLUSH:
                doca_offload_flush_item(offload);
                break;
            default:
                OVS_NOT_REACHED();
            }

            now = time_usec();
            latency_us = now - offload->timestamp;
            mov_avg_cma_update(&ofl_thread->cma, latency_us);
            mov_avg_ema_update(&ofl_thread->ema, latency_us);

            doca_free_offload(offload);

            /* Do RCU synchronization at fixed interval. */
            if (now > next_rcu) {
                ovsrcu_quiesce();
                next_rcu = time_usec() + DOCA_OFFLOAD_QUIESCE_INTERVAL_US;
            }
        }

        atomic_read_relaxed(&ofl_thread->offload->offload_thread_shutdown,
                            &exiting);
    } while (!exiting);

exit_thread:
    mpsc_queue_release(queue);
    return NULL;
}

static void
doca_offload_threads_init(struct doca_offload *offload)
{
    /* The main thread is not an offload thread, but as it apply offload rules,
     * it needs its own ID. */
    offload->offload_threads = xcalloc(1 + offload->offload_thread_count,
                                       sizeof(struct doca_offload_thread));

    for (unsigned int tid = 0; tid < 1 + offload->offload_thread_count;
         tid++) {
        struct doca_offload_thread *thread;

        thread = &offload->offload_threads[tid];
        mpsc_queue_init(&thread->queue);
        atomic_init(&thread->enqueued_item, 0);
        mov_avg_cma_init(&thread->cma);
        mov_avg_ema_init(&thread->ema, 100);
        thread->offload = offload;
        if (tid > 0) {
            thread->thread = ovs_thread_create("doca_offload",
                                               doca_offload_thread_main,
                                               thread);
        }
    }
}

static long long int
doca_offload_get_timestamp(void)
{
    /* XXX: We should look for a better, more efficient way to obtain a
     *  timestamp in the fast path, if only used for gathering statistics. */
    return time_usec();
}

static void
doca_offload_flush_enqueue(struct doca_offload *offload, struct netdev *netdev,
                           struct ovs_barrier *barrier)
{
    unsigned int tid;
    long long int now_us = doca_offload_get_timestamp();

    if (!dpif_offload_enabled()) {
        return;
    }

    for (tid = 1; tid < 1 + offload->offload_thread_count; tid++) {
        struct doca_offload_thread_item *item;
        struct doca_offload_flush_item *flush;

        item = xmalloc(sizeof *item + sizeof *flush);
        item->type = DOCA_OFFLOAD_FLUSH;
        item->timestamp = now_us;

        flush = &item->data->flush;
        flush->netdev = netdev;
        flush->offload = offload;
        flush->barrier = barrier;

        doca_append_offload(offload, item, tid);
    }
}

/* Blocking call that will wait on the offload thread to
 * complete its work.  As the flush order will only be
 * enqueued after existing offload requests, those previous
 * offload requests must be processed.
 *
 * Flow offload flush is done when a port is being deleted.
 * Right before this call executes, the offload API is disabled
 * for the port.  This call must be made blocking until the
 * offload provider completed its job. */
static void
doca_offload_flush(struct doca_offload *offload, struct netdev *netdev)
{
    /* The flush mutex serves to exclude mutual access to the static
     * barrier, and to prevent multiple flush orders to several threads.
     *
     * The memory barrier needs to go beyond the function scope as
     * the other threads can resume from blocking after this function
     * already finished.
     *
     * Additionally, because the flush operation is blocking, it would
     * deadlock if multiple offload threads were blocking on several
     * different barriers.  Only allow a single flush order in the offload
     * queue at a time. */
    static struct ovs_mutex flush_mutex = OVS_MUTEX_INITIALIZER;
    static struct ovs_barrier barrier OVS_GUARDED_BY(flush_mutex);

    ovs_mutex_lock(&flush_mutex);

    ovs_barrier_init(&barrier, 1 + offload->offload_thread_count);

    doca_offload_flush_enqueue(offload, netdev, &barrier);
    ovs_barrier_block(&barrier);
    ovs_barrier_destroy(&barrier);

    ovs_mutex_unlock(&flush_mutex);
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

static int
doca_offload_enable(struct dpif_offload *offload_,
                    struct dpif_offload_port *port)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct netdev *netdev = port->netdev;

    doca_netdev_offload_init(netdev, offload->offload_thread_count);
    dpif_offload_set_netdev_offload(netdev, offload_);
    return 0;
}

static int
doca_offload_cleanup(struct dpif_offload *offload_ OVS_UNUSED,
                     struct dpif_offload_port *port)
{
    struct netdev *netdev = port->netdev;

    doca_netdev_offload_uninit(netdev);
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

struct foreach_aux {
    struct dpif_offload *offload;
    struct netdev_doca *esw_dev;
    struct rte_pci_addr *esw_pci;
    int (*user_cb)(struct dpif_offload *, struct netdev *, odp_port_t);
};

static bool
foreach_cb_wrapper(struct netdev *rep_netdev,
                   odp_port_t port_no,
                   void *aux_)
{
    struct foreach_aux *aux = aux_;
    struct netdev_doca *rep_dev;
    struct rte_pci_addr rep_pci;

    if (strcmp(netdev_get_type(rep_netdev), "doca")) {
        return false;
    }

    rep_dev = netdev_doca_cast(rep_netdev);

    if (aux->esw_dev == rep_dev) {
        return false;
    }

    if (!rep_dev->common.devargs ||
        netdev_doca_parse_dpdk_devargs_pci(rep_dev->common.devargs,
                                           &rep_pci)) {
        return false;
    }

    if (rte_pci_addr_cmp(&rep_pci, aux->esw_pci)) {
        return false;
    }

    aux->user_cb(aux->offload, rep_netdev, port_no);
    return false;
}

static void
doca_offload_foreach_rep(struct dpif_offload *offload_,
                         struct netdev *esw_netdev,
                         int (*user_cb)(struct dpif_offload *,
                                        struct netdev *,
                                        odp_port_t))
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct rte_pci_addr esw_pci;
    struct netdev_doca *esw_dev;
    struct foreach_aux aux;

    if (strcmp(netdev_get_type(esw_netdev), "doca")) {
        return;
    }

    esw_dev = netdev_doca_cast(esw_netdev);
    if (netdev_doca_parse_dpdk_devargs_pci(esw_dev->common.devargs,
                                           &esw_pci)) {
        return;
    }

    if (strstr(esw_dev->common.devargs, "representor=")) {
        return;
    }

    aux = (struct foreach_aux) {
        .offload = offload_,
        .esw_dev = esw_dev,
        .esw_pci = &esw_pci,
        .user_cb = user_cb,
    };
    doca_offload_traverse_ports(offload, foreach_cb_wrapper, &aux);
}

static int
doca_offload_port_add(struct dpif_offload *offload, struct netdev *netdev,
                      odp_port_t port_no)
{
    struct dpif_offload_port *port = xmalloc(sizeof *port);
    int rv;

    if (dpif_offload_port_mgr_add(offload, port, netdev, port_no, false)) {
        if (dpif_offload_enabled()) {
            rv = doca_offload_enable(offload, port);
            if (!rv) {
                doca_offload_foreach_rep(offload, netdev,
                                         doca_offload_port_add);
            }

            return rv;
        }

        return 0;
    }

    free(port);
    return EEXIST;
}

static void
doca_offload_free_port(struct dpif_offload_port *port)
{
    netdev_close(port->netdev);
    free(port);
}

static int
doca_offload_port_del(struct dpif_offload *offload_, odp_port_t port_no);

static int
doca_offload_port_del_(struct dpif_offload *offload_,
                       struct netdev *netdev OVS_UNUSED,
                       odp_port_t port_no)
{
    return doca_offload_port_del(offload_, port_no);
}

static int
doca_offload_port_del(struct dpif_offload *offload_, odp_port_t port_no)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct dpif_offload_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_find_by_odp_port(offload_, port_no);

    if (dpif_offload_enabled() && port) {
        doca_offload_foreach_rep(offload_, port->netdev,
                                 doca_offload_port_del_);
        /* If hardware offload is enabled, we first need to flush (complete)
         * all pending flow operations, especially the pending delete ones,
         * before we remove the netdev from the port_mgr list. */
        dpif_offload_set_netdev_offload(port->netdev, NULL);
        doca_offload_flush(offload, port->netdev);
    }

    port = dpif_offload_port_mgr_remove(offload_, port_no);
    if (port) {
        if (dpif_offload_enabled()) {
            ret = doca_offload_cleanup(offload_, port);
        }

        ovsrcu_postpone(doca_offload_free_port, port);
    }

    return ret;
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

static int
doca_offload_open(const struct dpif_offload_class *offload_class,
                  struct dpif *dpif, struct dpif_offload **offload_)
{
    struct doca_offload *offload = xmalloc(sizeof *offload);

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;
    offload->offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;
    offload->offload_threads = NULL;
    atomic_count_init(&offload->next_offload_thread_id, 0);
    atomic_init(&offload->offload_thread_shutdown, false);
    offload->unreference_cb = NULL;

    *offload_ = &offload->offload;
    return 0;
}

static void
doca_offload_close(struct dpif_offload *offload_)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct dpif_offload_port *port;

    DPIF_OFFLOAD_PORT_FOR_EACH (port, offload_) {
        doca_offload_port_del(offload_, port->port_no);
    }

    atomic_store_relaxed(&offload->offload_thread_shutdown, true);
    if (offload->offload_threads) {
        for (int i = 0; i < 1 + offload->offload_thread_count; i++) {
            if (i > 0) {
                xpthread_join(offload->offload_threads[i].thread, NULL);
            }

            mpsc_queue_destroy(&offload->offload_threads[i].queue);
        }

        free(offload->offload_threads);
    }

    ovsthread_once_destroy(&offload->once_enable);
    dpif_offload_destroy(offload_);
    free(offload);
}

static void
doca_offload_set_config(struct dpif_offload *offload_,
                        const struct smap *other_cfg)
{
    struct doca_offload *offload = doca_offload_cast(offload_);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {
            struct dpif_offload_port *port;

            unsigned int offload_thread_count = smap_get_uint(
                other_cfg, "n-offload-threads", DEFAULT_OFFLOAD_THREAD_COUNT);

            if (offload_thread_count == 0 ||
                offload_thread_count > MAX_OFFLOAD_THREAD_COUNT) {
                VLOG_WARN("netdev: Invalid number of threads requested: %u",
                          offload_thread_count);
                offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;
            }

            VLOG_INFO("Flow API using %u thread%s", offload_thread_count,
                      offload_thread_count > 1 ? "s" : "");

            offload->offload_thread_count = offload_thread_count;

            doca_offload_threads_init(offload);
            DPIF_OFFLOAD_PORT_FOR_EACH (port, offload_) {
                doca_offload_enable(offload_, port);
            }

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static void
doca_offload_get_debug(const struct dpif_offload *offload, struct ds *ds,
                       struct json *json)
{
    if (json) {
        struct json *json_ports = json_object_create();
        struct dpif_offload_port *port;

        DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
            struct json *json_port = json_object_create();

            json_object_put(json_port, "port_no",
                            json_integer_create(odp_to_u32(port->port_no)));

            json_object_put(json_ports, netdev_get_name(port->netdev),
                            json_port);
        }

        if (!json_object_is_empty(json_ports)) {
            json_object_put(json, "ports", json_ports);
        } else {
            json_destroy(json_ports);
        }
    } else if (ds) {
        struct dpif_offload_port *port;

        DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
            ds_put_format(ds, "  - %s: port_no: %u\n",
                          netdev_get_name(port->netdev), port->port_no);
        }
    }
}

static bool
doca_can_offload(struct dpif_offload *offload OVS_UNUSED,
                 struct netdev *netdev)
{
    return !strcmp(netdev_get_type(netdev), "doca");
}

static uint64_t
doca_offload_flow_count(const struct dpif_offload *offload_)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct dpif_offload_port *port;
    uint64_t total = 0;

    if (!dpif_offload_enabled()) {
        return 0;
    }

    DPIF_OFFLOAD_PORT_FOR_EACH (port, offload_) {
        total += doca_netdev_flow_count(port->netdev,
                                        offload->offload_thread_count);
    }

    return total;
}

static uint64_t
doca_offload_flow_count_by_thread(struct doca_offload *offload,
                                  unsigned int tid)
{
    struct dpif_offload_port *port;
    uint64_t total = 0;

    if (!dpif_offload_enabled()) {
        return 0;
    }

    DPIF_OFFLOAD_PORT_FOR_EACH (port, &offload->offload) {
        total += doca_netdev_flow_count_by_thread(port->netdev, tid);
    }

    return total;
}

static int
doca_offload_hw_post_process(const struct dpif_offload *offload_,
                             struct netdev *netdev, unsigned pmd_id,
                             struct dp_packet *packet, void **flow_reference)
{
    struct doca_offload *offload = doca_offload_cast(offload_);

    return doca_netdev_hw_miss_packet_recover(offload, netdev, pmd_id, packet,
                                              flow_reference);
}

static int
doca_enqueue_flow_put(const struct dpif_offload *offload_,
                      struct netdev *netdev OVS_UNUSED,
                      struct dpif_offload_flow_put *put,
                      void **previous_flow_reference OVS_UNUSED)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct doca_offload_thread_item *item;
    struct doca_offload_flow_item *flow_offload;

    item = doca_alloc_flow_offload(DOCA_NETDEV_FLOW_OFFLOAD_OP_PUT);
    item->timestamp = doca_offload_get_timestamp();

    flow_offload = &item->data->flow;
    flow_offload->in_port = put->in_port;
    flow_offload->ufid = *put->ufid;
    flow_offload->pmd_id = put->pmd_id;
    flow_offload->flow_reference = put->flow_reference;
    flow_offload->match = *put->match;
    flow_offload->actions = xmalloc(put->actions_len);
    nullable_memcpy(flow_offload->actions, put->actions, put->actions_len);
    flow_offload->actions_len = put->actions_len;
    flow_offload->orig_in_port = put->orig_in_port;
    flow_offload->requested_stats = !!put->stats;
    flow_offload->callback = put->cb_data;

    doca_offload_flow_enqueue(offload, item);
    return EINPROGRESS;
}

static int
doca_enqueue_flow_del(const struct dpif_offload *offload_,
                      struct netdev *netdev OVS_UNUSED,
                      struct dpif_offload_flow_del *del)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    struct doca_offload_thread_item *item;
    struct doca_offload_flow_item *flow_offload;

    item = doca_alloc_flow_offload(DOCA_NETDEV_FLOW_OFFLOAD_OP_DEL);
    item->timestamp =doca_offload_get_timestamp();

    flow_offload = &item->data->flow;
    flow_offload->in_port = del->in_port;
    flow_offload->requested_stats = !!del->stats;
    flow_offload->ufid = *del->ufid;
    flow_offload->flow_reference = del->flow_reference;
    flow_offload->pmd_id = del->pmd_id;
    flow_offload->callback = del->cb_data;

    doca_offload_flow_enqueue(offload, item);
    return EINPROGRESS;
}

static void
doca_register_flow_unreference_cb(const struct dpif_offload *offload_,
                                  dpif_offload_flow_unreference_cb *cb)
{
    struct doca_offload *offload = doca_offload_cast(offload_);

    offload->unreference_cb = cb;
}

void
doca_offload_unreference(struct doca_offload *offload, unsigned pmd_id,
                         void *flow_reference)
{
    if (offload->unreference_cb) {
        offload->unreference_cb(pmd_id, flow_reference);
    }
}

static bool
doca_offload_flow_stats(const struct dpif_offload *ol OVS_UNUSED,
                        struct netdev *netdev, const ovs_u128 *ufid,
                        struct dpif_flow_stats *stats,
                        struct dpif_flow_attrs *attrs)
{
    uint64_t act_buf[1024 / 8];
    struct nlattr *actions;
    struct match match;
    struct ofpbuf buf;

    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);

    return !doca_netdev_flow_get(netdev, &match, &actions, ufid, stats, attrs,
                                 &buf);
}

static int
doca_get_global_stats(const struct dpif_offload *offload_,
                      struct netdev_custom_stats *stats)
{
    struct doca_offload *offload = doca_offload_cast(offload_);
    unsigned int nb_thread = 1 + offload->offload_thread_count;
    struct doca_offload_thread *offload_threads = offload->offload_threads;
    unsigned int tid;
    size_t i;

    enum {
        DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED,
        DP_NETDEV_HW_OFFLOADS_STATS_INSERTED,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN,
        DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV,
    };
    struct {
        const char *name;
        uint64_t total;
    } hwol_stats[] = {
        [DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED] =
            { "                Enqueued offloads", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] =
            { "                Inserted offloads", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN] =
            { "  Cumulative Average latency (us)", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV] =
            { "   Cumulative Latency stddev (us)", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN] =
            { " Exponential Average latency (us)", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV] =
            { "  Exponential Latency stddev (us)", 0 },
    };

    if (!dpif_offload_enabled() || !nb_thread) {
        /* Leave stats structure untouched on error per API guidelines. */
        return EINVAL;
    }

    stats->label = xstrdup(dpif_offload_name(offload_));

    /* nb_thread counters for the overall total as well. */
    stats->size = ARRAY_SIZE(hwol_stats) * (nb_thread + 1);
    stats->counters = xcalloc(stats->size, sizeof *stats->counters);

    for (tid = 0; tid < nb_thread; tid++) {
        uint64_t counts[ARRAY_SIZE(hwol_stats)];
        size_t idx = ((tid + 1) * ARRAY_SIZE(hwol_stats));

        memset(counts, 0, sizeof counts);
        if (offload_threads) {
            counts[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] =
                doca_offload_flow_count_by_thread(offload, tid);

            atomic_read_relaxed(&offload_threads[tid].enqueued_item,
                                &counts[DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED]);

            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN] =
                mov_avg_cma(&offload_threads[tid].cma);
            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV] =
                mov_avg_cma_std_dev(&offload_threads[tid].cma);

            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN] =
                mov_avg_ema(&offload_threads[tid].ema);
            counts[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV] =
                mov_avg_ema_std_dev(&offload_threads[tid].ema);
        }

        for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
            snprintf(stats->counters[idx + i].name,
                     sizeof(stats->counters[idx + i].name),
                     "  [%3u] %s", tid, hwol_stats[i].name);
            stats->counters[idx + i].value = counts[i];
            hwol_stats[i].total += counts[i];
        }
    }

    /* Do an average of the average for the aggregate. */
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_MEAN].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_CMA_STDDEV].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_MEAN].total /= nb_thread;
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_LAT_EMA_STDDEV].total /= nb_thread;

    /* Get the total offload count. */
    hwol_stats[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED].total =
        doca_offload_flow_count(offload_);

    for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
        snprintf(stats->counters[i].name, sizeof(stats->counters[i].name),
                 "  Total %s", hwol_stats[i].name);
        stats->counters[i].value = hwol_stats[i].total;
    }

    return 0;
}

struct dpif_offload_class dpif_offload_doca_class = {
    .type = "doca",
    .impl_type = DPIF_OFFLOAD_IMPL_FLOWS_DPIF_SYNCED,
    .supported_dpif_types = (const char *const[]) {"netdev", NULL},
    .open = doca_offload_open,
    .close = doca_offload_close,
    .set_config = doca_offload_set_config,
    .get_debug = doca_offload_get_debug,
    .get_global_stats = doca_get_global_stats,
    .can_offload = doca_can_offload,
    .port_add = doca_offload_port_add,
    .port_del = doca_offload_port_del,
    .flow_count = doca_offload_flow_count,
    .get_netdev = doca_offload_get_netdev__,
    .netdev_hw_post_process = doca_offload_hw_post_process,
    .netdev_flow_put = doca_enqueue_flow_put,
    .netdev_flow_del = doca_enqueue_flow_del,
    .netdev_flow_stats = doca_offload_flow_stats,
    .register_flow_unreference_cb = doca_register_flow_unreference_cb,
};
