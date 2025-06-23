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
#include "dpif-offload-rte_flow-private.h"
#include "id-fpool.h"
#include "mov-avg.h"
#include "mpsc-queue.h"
#include "netdev-offload-dpdk.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"
#include "uuid.h"

#include "openvswitch/json.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_rte_flow);

#define DEFAULT_OFFLOAD_THREAD_COUNT 1
#define MAX_OFFLOAD_THREAD_COUNT 10

enum rte_offload_type {
    RTE_OFFLOAD_FLOW,
    RTE_OFFLOAD_FLUSH,
};

enum {
    RTE_NETDEV_FLOW_OFFLOAD_OP_ADD,
    RTE_NETDEV_FLOW_OFFLOAD_OP_MOD,
    RTE_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

struct rte_offload_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        atomic_uint64_t enqueued_item;
        struct cmap megaflow_to_mark;
        struct mov_avg_cma cma;
        struct mov_avg_ema ema;
        atomic_llong time_now;
        struct dpif_offload_rte_flow *offload;
        pthread_t thread;
    );
};

struct rte_offload_flow_item {
    int op;
    odp_port_t in_port;
    ovs_u128 ufid;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;
    odp_port_t orig_in_port; /* Originating in_port for tunnel flows. */
    bool requested_stats;
    struct dpif_offload_flow_cb_data callback;
};

struct rte_offload_flush_item {
    struct netdev *netdev;
    struct dpif_offload_rte_flow *offload;
    struct ovs_barrier *barrier;
};

union rte_offload_thread_data {
    struct rte_offload_flow_item flow;
    struct rte_offload_flush_item flush;
};

struct rte_offload_thread_item {
    struct mpsc_queue_node node;
    enum rte_offload_type type;
    long long int timestamp;
    union rte_offload_thread_data data[0];
};

/* dpif offload interface for the rte implementation. */
struct dpif_offload_rte_flow {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    atomic_count next_offload_thread_id;
    atomic_bool offload_thread_shutdown;
    struct rte_offload_thread *offload_threads;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
    unsigned int offload_thread_count; /* Number of offload threads. */
};

static struct dpif_offload_rte_flow *
dpif_offload_rte_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_rte_flow_class);
    return CONTAINER_OF(offload, struct dpif_offload_rte_flow, offload);
}

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, rte_flow_offload_thread_id);
DEFINE_EXTERN_PER_THREAD_DATA(rte_flow_offload_thread_id, OVSTHREAD_ID_UNSET);

unsigned int
rte_flow_offload_thread_id(void)
{
    unsigned int id = *rte_flow_offload_thread_id_get();

    if (OVS_UNLIKELY(id == OVSTHREAD_ID_UNSET)) {
        /* Offload threads get their ID set at initialization, here
         * only the RCU thread might need initialization. */
        ovs_assert(!strncmp(get_subprogram_name(), "urcu", strlen("urcu")));

        /* RCU will compete with other threads for shared object access.
         * Reclamation functions using a thread ID must be thread-safe.
         * For that end, and because RCU must consider all potential shared
         * objects anyway, its thread-id can be whichever, so return 0.
         */
        id = 0;
        *rte_flow_offload_thread_id_get() = id;
    }

    return id;
}

static unsigned int
dpif_offload_rte_ufid_to_thread_id(struct dpif_offload_rte_flow *offload,
                                   const ovs_u128 ufid)
{
    uint32_t ufid_hash;

    if (offload->offload_thread_count == 1) {
        return 0;
    }

    ufid_hash = hash_words64_inline(
            (const uint64_t [2]){ ufid.u64.lo,
                                  ufid.u64.hi }, 2, 1);
    return ufid_hash % offload->offload_thread_count;
}

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

static inline uint32_t
rte_offload_ufid_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

/* Associate megaflow with a mark, which is a 1:1 mapping. */
static void
megaflow_to_mark_associate(struct dpif_offload_rte_flow *offload,
                           const ovs_u128 *mega_ufid, uint32_t mark)
{
    uint32_t hash = rte_offload_ufid_hash(mega_ufid);
    struct megaflow_to_mark_data *data = xzalloc(sizeof(*data));
    unsigned int tid = rte_flow_offload_thread_id();

    data->mega_ufid = *mega_ufid;
    data->mark = mark;

    cmap_insert(&offload->offload_threads[tid].megaflow_to_mark,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

/* Disassociate megaflow with a mark. */
static uint32_t
megaflow_to_mark_disassociate(struct dpif_offload_rte_flow *offload,
                              const ovs_u128 *mega_ufid)
{
    uint32_t hash = rte_offload_ufid_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = rte_flow_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &offload->offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            cmap_remove(&offload->offload_threads[tid].megaflow_to_mark,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return data->mark;
        }
    }

    VLOG_WARN("Masked ufid "UUID_FMT" is not associated with a mark?",
              UUID_ARGS((struct uuid *) mega_ufid));

    return INVALID_FLOW_MARK;
}

static inline uint32_t
megaflow_to_mark_find(struct dpif_offload_rte_flow *offload,
                      const ovs_u128 *mega_ufid)
{
    uint32_t hash = rte_offload_ufid_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = rte_flow_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &offload->offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_DBG("Mark id for ufid "UUID_FMT" was not found",
             UUID_ARGS((struct uuid *) mega_ufid));
    return INVALID_FLOW_MARK;
}

static bool
dpif_offload_rte_is_offloading_netdev(struct dpif_offload_rte_flow *offload,
                                      struct netdev *netdev)
{
    const struct dpif_offload *netdev_offload;

    netdev_offload = ovsrcu_get(const struct dpif_offload *,
                                &netdev->dpif_offload);

    return netdev_offload == &offload->offload;
}

static struct rte_offload_thread_item *
dpif_offload_rte_alloc_flow_offload(int op)
{
    struct rte_offload_thread_item *item;
    struct rte_offload_flow_item *flow_offload;

    item = xzalloc(sizeof *item + sizeof *flow_offload);
    flow_offload = &item->data->flow;

    item->type = RTE_OFFLOAD_FLOW;
    flow_offload->op = op;

    return item;
}

static void
dpif_offload_rte_free_flow_offload__(struct rte_offload_thread_item *offload)
{
    struct rte_offload_flow_item *flow_offload = &offload->data->flow;

    free(flow_offload->actions);
    free(offload);
}

static void
dpif_offload_rte_free_flow_offload(struct rte_offload_thread_item *offload)
{
    ovsrcu_postpone(dpif_offload_rte_free_flow_offload__, offload);
}

static void
dpif_offload_rte_free_offload(struct rte_offload_thread_item *offload)
{
    switch (offload->type) {
    case RTE_OFFLOAD_FLOW:
        dpif_offload_rte_free_flow_offload(offload);
        break;
    case RTE_OFFLOAD_FLUSH:
        free(offload);
        break;
    default:
        OVS_NOT_REACHED();
    };
}

static void
dpif_offload_rte_append_offload(const struct dpif_offload_rte_flow *offload,
                                struct rte_offload_thread_item *item,
                                unsigned int tid)
{
    ovs_assert(offload->offload_threads);

    mpsc_queue_insert(&offload->offload_threads[tid].queue, &item->node);
    atomic_count_inc64(&offload->offload_threads[tid].enqueued_item);
}

static void
dpif_offload_rte_offload_flow_enqueue(struct dpif_offload_rte_flow *offload,
                                      struct rte_offload_thread_item *item)
{
    struct rte_offload_flow_item *flow_offload = &item->data->flow;
    unsigned int tid;

    ovs_assert(item->type == RTE_OFFLOAD_FLOW);

    tid = dpif_offload_rte_ufid_to_thread_id(offload, flow_offload->ufid);
    dpif_offload_rte_append_offload(offload, item, tid);
}

static int
dpif_offload_rte_flow_offload_del(struct rte_offload_thread *thread,
                                  struct rte_offload_thread_item *item)
{
    struct rte_offload_flow_item *flow = &item->data->flow;
    uint32_t mark = INVALID_FLOW_MARK;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    int error;

    netdev = dpif_offload_rte_get_netdev(thread->offload, flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    error = netdev_offload_dpdk_flow_del(netdev, &flow->ufid,
                                         flow->requested_stats ? &stats
                                                               : NULL);

    mark = megaflow_to_mark_disassociate(thread->offload, &flow->ufid);

do_callback:
    dpif_offload_datapath_flow_op_continue(&flow->callback,
                                           flow->requested_stats ? &stats
                                                                 : NULL,
                                           mark, error);
    return error;
}

static int
dpif_offload_rte_flow_offload_put(struct rte_offload_thread *thread,
                                  struct rte_offload_thread_item *item,
                                  bool modify)
{
    struct rte_offload_flow_item *flow = &item->data->flow;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    uint32_t mark;
    int error = 0;

    mark = megaflow_to_mark_find(thread->offload, &flow->ufid);
    if (modify) {
        if (mark == INVALID_FLOW_MARK) {
            /* We have not offloaded this flow, so we can not modify it. */
            error = ENOENT;
            goto do_callback;
        }
    } else {
        if (mark != INVALID_FLOW_MARK) {
            VLOG_DBG("Flow has already been offloaded with mark %u", mark);
            goto do_callback;
        }

        mark = dpif_offload_allocate_flow_mark();
        if (mark == INVALID_FLOW_MARK) {
            VLOG_ERR("Failed to allocate flow mark!");
            error = ENOSPC;
            goto do_callback;
        }
    }

    netdev = dpif_offload_rte_get_netdev(thread->offload, flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    if (!dpif_offload_rte_is_offloading_netdev(thread->offload, netdev)) {
        error = EUNATCH;
        goto do_callback;
    }

    error = netdev_offload_dpdk_flow_put(
        thread->offload, netdev, &flow->match,
        CONST_CAST(struct nlattr *, flow->actions), flow->actions_len,
        &flow->ufid, mark, flow->orig_in_port,
        flow->requested_stats ? &stats : NULL);

do_callback:
    if (!error && !modify) {
        megaflow_to_mark_associate(thread->offload, &flow->ufid, mark);
    } else if (error) {
        if (modify) {
            /* We failed the modification, so the flow is no longer
             * installed, remove the mapping. */
            if (mark != INVALID_FLOW_MARK) {
                megaflow_to_mark_disassociate(thread->offload, &flow->ufid);
            }
        } else if (mark != INVALID_FLOW_MARK) {
            /* We allocated a mark, but it was not used. */
            dpif_offload_free_flow_mark(mark);
            mark = INVALID_FLOW_MARK;
        }
    }

    dpif_offload_datapath_flow_op_continue(&flow->callback,
                                            flow->requested_stats ? &stats
                                                                  : NULL,
                                            mark, error);
    return error;
}

static void
dpif_offload_rte_offload_flow(struct rte_offload_thread *thread,
                              struct rte_offload_thread_item *item)
{
    struct rte_offload_flow_item *flow_offload = &item->data->flow;
    const char *op;
    int ret;

    switch (flow_offload->op) {
    case RTE_NETDEV_FLOW_OFFLOAD_OP_ADD:
        op = "add";
        ret = dpif_offload_rte_flow_offload_put(thread, item, false);
        break;
    case RTE_NETDEV_FLOW_OFFLOAD_OP_MOD:
        op = "modify";
        ret = dpif_offload_rte_flow_offload_put(thread, item, true);
        break;
    case RTE_NETDEV_FLOW_OFFLOAD_OP_DEL:
        op = "delete";
        ret = dpif_offload_rte_flow_offload_del(thread, item);
        break;
    default:
        OVS_NOT_REACHED();
    }

    VLOG_DBG("%s to %s netdev flow "UUID_FMT,
             ret == 0 ? "succeed" : "failed", op,
             UUID_ARGS((struct uuid *) &flow_offload->ufid));
}

static void
dpif_offload_rte_offload_flush(struct rte_offload_thread_item *item)
{
    struct rte_offload_flush_item *flush = &item->data->flush;

    netdev_offload_dpdk_flow_flush(flush->offload, flush->netdev);
    ovs_barrier_block(flush->barrier);
}

#define RTE_OFFLOAD_BACKOFF_MIN 1
#define RTE_OFFLOAD_BACKOFF_MAX 64
#define RTE_OFFLOAD_QUIESCE_INTERVAL_US (10 * 1000) /* 10 ms */

static void *
dpif_offload_rte_offload_thread_main(void *arg)
{
    struct rte_offload_thread *ofl_thread = arg;
    struct rte_offload_thread_item *offload;
    struct mpsc_queue_node *node;
    struct mpsc_queue *queue;
    long long int latency_us;
    long long int next_rcu;
    long long int now;
    uint64_t backoff;
    bool exiting;

    if (*rte_flow_offload_thread_id_get() == OVSTHREAD_ID_UNSET) {
        unsigned int id;

        id = atomic_count_inc(&ofl_thread->offload->next_offload_thread_id);

        /* Panic if any offload thread is getting a spurious ID. */
        ovs_assert(id < ofl_thread->offload->offload_thread_count);

        *rte_flow_offload_thread_id_get() = id;
    }

    queue = &ofl_thread->queue;
    mpsc_queue_acquire(queue);

    do {
        backoff = RTE_OFFLOAD_BACKOFF_MIN;
        while (mpsc_queue_tail(queue) == NULL) {
            now = time_usec();
            atomic_store_relaxed(&ofl_thread->time_now, now);

            xnanosleep(backoff * 1E6);
            if (backoff < RTE_OFFLOAD_BACKOFF_MAX) {
                backoff <<= 1;
            }

            atomic_read_relaxed(&ofl_thread->offload->offload_thread_shutdown,
                                &exiting);
            if (exiting) {
                goto exit_thread;
            }
        }

        now = time_usec();
        atomic_store_relaxed(&ofl_thread->time_now, now);

        next_rcu = now + RTE_OFFLOAD_QUIESCE_INTERVAL_US;
        MPSC_QUEUE_FOR_EACH_POP (node, queue) {
            offload = CONTAINER_OF(node, struct rte_offload_thread_item, node);
            atomic_count_dec64(&ofl_thread->enqueued_item);

            switch (offload->type) {
            case RTE_OFFLOAD_FLOW:
                dpif_offload_rte_offload_flow(ofl_thread, offload);
                break;
            case RTE_OFFLOAD_FLUSH:
                dpif_offload_rte_offload_flush(offload);
                break;
            default:
                OVS_NOT_REACHED();
            }

            now = time_usec();
            atomic_store_relaxed(&ofl_thread->time_now, now);

            latency_us = now - offload->timestamp;
            mov_avg_cma_update(&ofl_thread->cma, latency_us);
            mov_avg_ema_update(&ofl_thread->ema, latency_us);

            dpif_offload_rte_free_offload(offload);

            /* Do RCU synchronization at fixed interval. */
            if (now > next_rcu) {
                ovsrcu_quiesce();
                next_rcu = time_usec() + RTE_OFFLOAD_QUIESCE_INTERVAL_US;
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
dpif_offload_rte_offload_threads_init(struct dpif_offload_rte_flow *offload)
{
    long long int now = time_usec();

    offload->offload_threads = xcalloc(offload->offload_thread_count,
                                       sizeof(struct rte_offload_thread));

    for (unsigned int tid = 0; tid < offload->offload_thread_count; tid++) {
        struct rte_offload_thread *thread;

        thread = &offload->offload_threads[tid];
        mpsc_queue_init(&thread->queue);
        cmap_init(&thread->megaflow_to_mark);
        atomic_init(&thread->enqueued_item, 0);
        mov_avg_cma_init(&thread->cma);
        mov_avg_ema_init(&thread->ema, 100);
        atomic_store_relaxed(&thread->time_now, now);
        thread->offload = offload;
        thread->thread = ovs_thread_create(
            "rte_offload", dpif_offload_rte_offload_thread_main, thread);
    }
}

static long long int
dpif_offload_rte_get_thread_timestamp(struct dpif_offload_rte_flow *offload,
                                      const ovs_u128 *ufid)
{
    unsigned int tid = dpif_offload_rte_ufid_to_thread_id(offload, *ufid);
    long long int time_now;

    atomic_read_relaxed(&offload->offload_threads[tid].time_now, &time_now);
    return time_now;
    /* XXX: Needs fixing as this time_now might be delayed by 64ms due to
     *      thread scheduling, maybe just call time_usec() directly. */
}

static void
dpif_offload_rte_flush_enqueue(struct dpif_offload_rte_flow *offload,
                               struct netdev *netdev,
                               struct ovs_barrier *barrier)
{
    unsigned int tid;
    long long int now_us = time_usec();

    if (!dpif_offload_is_offload_enabled()) {
        return;
    }

    for (tid = 0; tid < offload->offload_thread_count; tid++) {
        struct rte_offload_thread_item *item;
        struct rte_offload_flush_item *flush;

        item = xmalloc(sizeof *item + sizeof *flush);
        item->type = RTE_OFFLOAD_FLUSH;
        item->timestamp = now_us;

        flush = &item->data->flush;
        flush->netdev = netdev;
        flush->offload = offload;
        flush->barrier = barrier;

        dpif_offload_rte_append_offload(offload, item, tid);
    }
}

/* Blocking call that will wait on the offload thread to
 * complete its work.  As the flush order will only be
 * enqueued after existing offload requests, those previous
 * offload requests must be processed.
 *
 * Flow offload flush is done when a port is being deleted.
 * Right before this call executes, the offload API is disabled
 * for the port. This call must be made blocking until the
 * offload provider completed its job.
 */
static void
dpif_offload_rte_flush(struct dpif_offload_rte_flow *offload,
                       struct netdev *netdev)
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
     * different barriers. Only allow a single flush order in the offload
     * queue at a time.
     */
    static struct ovs_mutex flush_mutex = OVS_MUTEX_INITIALIZER;
    static struct ovs_barrier barrier OVS_GUARDED_BY(flush_mutex);

    ovs_mutex_lock(&flush_mutex);

    ovs_barrier_init(&barrier, 1 + offload->offload_thread_count);

    dpif_offload_rte_flush_enqueue(offload, netdev, &barrier);
    ovs_barrier_block(&barrier);
    ovs_barrier_destroy(&barrier);

    ovs_mutex_unlock(&flush_mutex);
}

void dpif_offload_rte_traverse_ports(
    const struct dpif_offload_rte_flow *offload,
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux)
{
    struct dpif_offload_port_mgr_port *port;

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        if (cb(port->netdev, port->port_no, aux)) {
            break;
        }
    }
}

static int
dpif_offload_rte_enable_offload(struct dpif_offload *offload_,
                                struct dpif_offload_port_mgr_port *port)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);
    struct netdev *netdev = port->netdev;

    netdev_offload_dpdk_init(netdev, offload->offload_thread_count);
    dpif_offload_set_netdev_offload(netdev, offload_);
    return 0;
}

static int
dpif_offload_rte_cleanup_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                                 struct dpif_offload_port_mgr_port *port)
{
    struct netdev *netdev = port->netdev;

    netdev_offload_dpdk_uninit(netdev);
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

    port = dpif_offload_port_mgr_find_by_odp_port(offload_rte->port_mgr,
                                                  port_no);

    if (dpif_offload_is_offload_enabled() && port) {
        /* If hardware offload is enabled, we first need to flush (complete)
         * all pending flow operations, especially the pending delete ones,
         * before we remove the netdev from the port_mgr list.
         */
        dpif_offload_set_netdev_offload(port->netdev, NULL);
        dpif_offload_rte_flush(offload_rte, port->netdev);
    }

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
dpif_offload_rte_port_dump_start(const struct dpif_offload *offload_,
                                 void **statep)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);

    return dpif_offload_port_mgr_port_dump_start(offload->port_mgr, statep);
}

static int
dpif_offload_rte_port_dump_next(const struct dpif_offload *offload_,
                                void *state,
                                struct dpif_offload_port *port)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);

    return dpif_offload_port_mgr_port_dump_next(offload->port_mgr, state,
                                                port);
}

static int
dpif_offload_rte_port_dump_done(const struct dpif_offload *offload_,
                                void *state)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);

    return dpif_offload_port_mgr_port_dump_done(offload->port_mgr, state);
}

struct netdev *
dpif_offload_rte_get_netdev(struct dpif_offload_rte_flow *offload,
                            odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(offload->port_mgr,
                                                  port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static struct netdev *
dpif_offload_rte_get_netdev_(struct dpif_offload *offload,
                             odp_port_t port_no)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);

    return dpif_offload_rte_get_netdev(offload_rte, port_no);
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
    offload_rte->offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;
    offload_rte->offload_threads = NULL;
    atomic_count_init(&offload_rte->next_offload_thread_id, 0);
    atomic_init(&offload_rte->offload_thread_shutdown, false);

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

    atomic_store_relaxed(&offload_rte->offload_thread_shutdown, true);
    if (offload_rte->offload_threads) {
        for (int i = 0; i < offload_rte->offload_thread_count; i++) {
            xpthread_join(offload_rte->offload_threads[i].thread, NULL);
        }
    }
    free(offload_rte);
}

static bool dpif_offload_rte_late_enable(struct dpif_offload_port_mgr_port *p,
                                         void *aux)
{
    dpif_offload_rte_enable_offload(aux, p);
    return false;
}

static void
dpif_offload_rte_set_config(struct dpif_offload *offload_,
                           const struct smap *other_cfg)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);

    /* We maintain the existing behavior where global configurations
     * are only accepted when hardware offload is initially enabled.
     * Once enabled, they cannot be updated or reconfigured. */
    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {

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

            dpif_offload_rte_offload_threads_init(offload);
            dpif_offload_port_mgr_traverse_ports(offload->port_mgr,
                                                 dpif_offload_rte_late_enable,
                                                 offload);

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static bool
dpif_offload_rte_get_port_debug_ds(struct dpif_offload_port_mgr_port *port,
                                   void *aux)
{
    struct ds *ds = aux;

    ds_put_format(ds, "  - %s: port_no: %u\n",
                  netdev_get_name(port->netdev), port->port_no);

    return false;
}

static bool
dpif_offload_rte_get_port_debug_json(struct dpif_offload_port_mgr_port *port,
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
dpif_offload_rte_get_debug(const struct dpif_offload *offload, struct ds *ds,
                           struct json *json)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);

    if (json) {
        struct json *json_ports = json_object_create();

        dpif_offload_port_mgr_traverse_ports(
            offload_rte->port_mgr, dpif_offload_rte_get_port_debug_json,
            json_ports);

        if (!json_object_is_empty(json_ports)) {
            json_object_put(json, "ports", json_ports);
        } else {
            json_destroy(json_ports);
        }

    } else if (ds) {
        dpif_offload_port_mgr_traverse_ports(
            offload_rte->port_mgr, dpif_offload_rte_get_port_debug_ds, ds);
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

struct get_n_offload_cb_aux {
    uint64_t *total;
    union {
        unsigned int offload_thread_count;
        unsigned int offload_thread_id;
    };
};

static bool
dpif_offload_rte_flow_get_n_offloaded_cb(
    struct dpif_offload_port_mgr_port *port, void *aux_)
{
    struct get_n_offload_cb_aux *aux = aux_;

    *aux->total += netdev_offload_dpdk_flow_get_n_offloaded(
        port->netdev, aux->offload_thread_count);
    return false;
}

static uint64_t
dpif_offload_rte_flow_get_n_offloaded(const struct dpif_offload *offload)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);
    uint64_t total = 0;

    struct get_n_offload_cb_aux aux = {
        .offload_thread_count = offload_rte->offload_thread_count,
        .total = &total,
    };

    if (!dpif_offload_is_offload_enabled()) {
        return 0;
    }

    dpif_offload_port_mgr_traverse_ports(
        offload_rte->port_mgr, dpif_offload_rte_flow_get_n_offloaded_cb,
        &aux);

    return total;
}

static bool
dpif_offload_rte_flow_get_n_offloaded_by_thread_cb(
    struct dpif_offload_port_mgr_port *port, void *aux_)
{
    struct get_n_offload_cb_aux *aux = aux_;

    *aux->total += netdev_offload_dpdk_flow_get_n_offloaded_by_thread(
        port->netdev, aux->offload_thread_id);
    return false;
}

static uint64_t
dpif_offload_rte_flow_get_n_offloaded_by_thread(
    struct dpif_offload_rte_flow *offload, unsigned int tid)
{
    uint64_t total = 0;

    struct get_n_offload_cb_aux aux = {
        .offload_thread_id = tid,
        .total = &total,
    };

    if (!dpif_offload_is_offload_enabled()) {
        return 0;
    }

    dpif_offload_port_mgr_traverse_ports(
        offload->port_mgr,
        dpif_offload_rte_flow_get_n_offloaded_by_thread_cb,
        &aux);

    return total;
}

static int
dpif_offload_rte_netdev_hw_miss_packet_recover(
    const struct dpif_offload *offload_, struct netdev *netdev,
    struct dp_packet *packet)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);

    return netdev_offload_dpdk_hw_miss_packet_recover(offload, netdev, packet);
}

static int
dpif_offload_rte_netdev_flow_put(const struct dpif_offload *offload_,
                                 struct netdev *netdev OVS_UNUSED,
                                 struct dpif_offload_flow_put *put,
                                 uint32_t *flow_mark)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);
    struct rte_offload_thread_item *item;
    struct rte_offload_flow_item *flow_offload;

    item = dpif_offload_rte_alloc_flow_offload(
        put->modify ? RTE_NETDEV_FLOW_OFFLOAD_OP_MOD
                    : RTE_NETDEV_FLOW_OFFLOAD_OP_ADD);

    flow_offload = &item->data->flow;
    flow_offload->in_port = put->in_port;
    flow_offload->ufid = *put->ufid;
    flow_offload->match = *put->match;
    flow_offload->actions = xmalloc(put->actions_len);
    nullable_memcpy(flow_offload->actions, put->actions, put->actions_len);
    flow_offload->actions_len = put->actions_len;
    flow_offload->orig_in_port = put->orig_in_port;
    flow_offload->requested_stats = !!put->stats;
    flow_offload->callback = put->cb_data;

    item->timestamp = dpif_offload_rte_get_thread_timestamp(offload,
                                                            put->ufid);
    dpif_offload_rte_offload_flow_enqueue(offload, item);

    *flow_mark = INVALID_FLOW_MARK;
    return EINPROGRESS;
}

static int
dpif_offload_rte_netdev_flow_del(const struct dpif_offload *offload_,
                                 struct netdev *netdev OVS_UNUSED,
                                 struct dpif_offload_flow_del *del,
                                 uint32_t *flow_mark)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);
    struct rte_offload_thread_item *item;
    struct rte_offload_flow_item *flow_offload;

    item = dpif_offload_rte_alloc_flow_offload(RTE_NETDEV_FLOW_OFFLOAD_OP_DEL);

    flow_offload = &item->data->flow;
    flow_offload->in_port = del->in_port;
    flow_offload->requested_stats = !!del->stats;
    flow_offload->ufid = *del->ufid;
    flow_offload->callback = del->cb_data;

    item->timestamp = dpif_offload_rte_get_thread_timestamp(offload,
                                                            del->ufid);
    dpif_offload_rte_offload_flow_enqueue(offload, item);

    *flow_mark = INVALID_FLOW_MARK;
    return EINPROGRESS;
}

static bool
dpif_offload_rte_netdev_flow_stats(const struct dpif_offload *ol OVS_UNUSED,
                                   struct netdev *netdev,
                                   const ovs_u128 *ufid,
                                   struct dpif_flow_stats *stats,
                                   struct dpif_flow_attrs *attrs)
{
    uint64_t act_buf[1024 / 8];
    struct nlattr *actions;
    struct match match;
    struct ofpbuf buf;

    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);

    return !netdev_offload_dpdk_flow_get(netdev, &match, &actions,
                                         ufid, stats, attrs, &buf);
}

static int
dpif_offload_rte_get_global_stats(const struct dpif_offload *offload_,
                                  struct netdev_custom_stats *stats)
{
    struct dpif_offload_rte_flow *offload = dpif_offload_rte_cast(offload_);
    unsigned int nb_thread = offload->offload_thread_count;
    struct rte_offload_thread *offload_threads = offload->offload_threads;
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

    if (!dpif_offload_is_offload_enabled() || !nb_thread) {
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
        if (offload_threads != NULL) {
            counts[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] =
                dpif_offload_rte_flow_get_n_offloaded_by_thread(offload, tid);

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
        dpif_offload_rte_flow_get_n_offloaded(offload_);

    for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
        snprintf(stats->counters[i].name, sizeof(stats->counters[i].name),
                 "  Total %s", hwol_stats[i].name);
        stats->counters[i].value = hwol_stats[i].total;
    }

    return 0;
}

struct dpif_offload_class dpif_offload_rte_flow_class = {
    .type = "rte_flow",
    .impl_type = DPIF_OFFLOAD_IMPL_SYNC,
    .supported_dpif_types = (const char *const[]) {
        "netdev",
        NULL},
    .open = dpif_offload_rte_open,
    .close = dpif_offload_rte_close,
    .set_config = dpif_offload_rte_set_config,
    .get_debug = dpif_offload_rte_get_debug,
    .get_global_stats = dpif_offload_rte_get_global_stats,
    .can_offload = dpif_offload_rte_can_offload,
    .port_add = dpif_offload_rte_port_add,
    .port_del = dpif_offload_rte_port_del,
    .port_dump_start = dpif_offload_rte_port_dump_start,
    .port_dump_next = dpif_offload_rte_port_dump_next,
    .port_dump_done = dpif_offload_rte_port_dump_done,
    .flow_get_n_offloaded = dpif_offload_rte_flow_get_n_offloaded,
    .get_netdev = dpif_offload_rte_get_netdev_,
    .netdev_hw_miss_packet_recover = \
        dpif_offload_rte_netdev_hw_miss_packet_recover,
    .netdev_flow_put = dpif_offload_rte_netdev_flow_put,
    .netdev_flow_del = dpif_offload_rte_netdev_flow_del,
    .netdev_flow_stats = dpif_offload_rte_netdev_flow_stats,
};
