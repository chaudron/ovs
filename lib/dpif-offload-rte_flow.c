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

//XXX: These below includes should be removed once completed.
#include "dpif-netdev.h"
#include "dpif-netdev-private-flow.h"
#include "dpif-netdev-private-thread.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_rte_flow);

#define DEFAULT_OFFLOAD_THREAD_COUNT 1
#define MAX_OFFLOAD_THREAD_COUNT 10

/* Forward function declarations. */
static struct netdev *dpif_offload_rte_flow_get_netdev(struct dpif_offload *,
                                                       odp_port_t);

struct dp_netdev; /* XXX: External declaration, should be removed. */

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
        struct cmap mark_to_flow;  //XXX: To be removed...
        struct mov_avg_cma cma;
        struct mov_avg_ema ema;
        atomic_llong time_now;
        struct dpif_offload_rte_flow *offload;
    );
};

struct rte_offload_flow_item {
    struct dp_netdev_flow *flow;
    int op;
    odp_port_t in_port;
    ovs_u128 ufid;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;
    odp_port_t orig_in_port; /* Originating in_port for tnl flows. */
    bool requested_stats;
    struct dpif_offload_flow_cb_data callback;
};

struct rte_offload_flush_item {
    struct netdev *netdev;
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
    struct dp_netdev *dp;
    union rte_offload_thread_data data[0];
};

/* dpif offload interface for the tc implementation. */
struct dpif_offload_rte_flow {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    struct rte_offload_thread *offload_threads;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
    unsigned int offload_thread_count; /* Number of offload threads. */
};

//XXX: This should move to the dpif_offload_rte_flow structure above.
static struct rte_offload_thread *offload_threads;
static unsigned int rte_offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;

/* XXX: External reference, will be removed after full integration. */
unsigned int rte_flow_offload_thread_id(void);

DECLARE_EXTERN_PER_THREAD_DATA(unsigned int, rte_flow_offload_thread_id);
DEFINE_EXTERN_PER_THREAD_DATA(rte_flow_offload_thread_id, OVSTHREAD_ID_UNSET);

static unsigned int
rte_flow_offload_thread_init(void)
{
    static atomic_count next_id = ATOMIC_COUNT_INIT(0);
    bool thread_is_hw_offload;
    bool thread_is_rcu;

    thread_is_hw_offload = !strncmp(get_subprogram_name(),
                                    "rte_offload", strlen("rte_offload"));
    thread_is_rcu = !strncmp(get_subprogram_name(), "urcu", strlen("urcu"));

    /* Panic if any other thread besides offload and RCU tries
     * to initialize their thread ID. */
    ovs_assert(thread_is_hw_offload || thread_is_rcu);

    if (*rte_flow_offload_thread_id_get() == OVSTHREAD_ID_UNSET) {
        unsigned int id;

        if (thread_is_rcu) {
            /* RCU will compete with other threads for shared object access.
             * Reclamation functions using a thread ID must be thread-safe.
             * For that end, and because RCU must consider all potential shared
             * objects anyway, its thread-id can be whichever, so return 0.
             */
            id = 0;
        } else {
            /* Only the actual offload threads have their own ID. */
            id = atomic_count_inc(&next_id);
        }
        /* Panic if any offload thread is getting a spurious ID. */
        ovs_assert(id < rte_offload_thread_count);
        return *rte_flow_offload_thread_id_get() = id;
    } else {
        return *rte_flow_offload_thread_id_get();
    }
}

unsigned int
rte_flow_offload_thread_id(void)
{
    unsigned int id = *rte_flow_offload_thread_id_get();

    if (OVS_UNLIKELY(id == OVSTHREAD_ID_UNSET)) {
        id = rte_flow_offload_thread_init();
    }

    return id;
}

static unsigned int
dpif_offload_rte_ufid_to_thread_id(const ovs_u128 ufid)
{
    uint32_t ufid_hash;

    if (rte_offload_thread_count == 1) {
        return 0;
    }

    ufid_hash = hash_words64_inline(
            (const uint64_t [2]){ ufid.u64.lo,
                                  ufid.u64.hi }, 2, 1);
    return ufid_hash % rte_offload_thread_count;
}

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

/* Associate megaflow with a mark, which is a 1:1 mapping. */
static void
megaflow_to_mark_associate(const ovs_u128 *mega_ufid, uint32_t mark)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data = xzalloc(sizeof(*data));
    unsigned int tid = rte_flow_offload_thread_id();

    data->mega_ufid = *mega_ufid;
    data->mark = mark;

    cmap_insert(&offload_threads[tid].megaflow_to_mark,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

/* Disassociate meagaflow with a mark. */
static uint32_t
megaflow_to_mark_disassociate(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = rte_flow_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            cmap_remove(&offload_threads[tid].megaflow_to_mark,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return data->mark;
        }
    }

    VLOG_WARN("Masked ufid "UUID_FMT" is not associated with a mark?\n",
              UUID_ARGS((struct uuid *)mega_ufid));

    return INVALID_FLOW_MARK;
}

static inline uint32_t
megaflow_to_mark_find(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = rte_flow_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_DBG("Mark id for ufid "UUID_FMT" was not found\n",
             UUID_ARGS((struct uuid *)mega_ufid));
    return INVALID_FLOW_MARK;
}

/* XXX: Temporarily external declarations, will be removed during cleanup. */
struct netdev *dpif_netdev_offload_get_netdev_by_port_id(odp_port_t);

static struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd,
                  const uint32_t mark)
{
    struct dp_netdev_flow *flow;
    unsigned int tid;
    size_t hash;

    if (offload_threads == NULL) {
        return NULL;
    }

    hash = hash_int(mark, 0);
    for (tid = 0; tid < rte_offload_thread_count; tid++) {
        CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash,
                                 &offload_threads[tid].mark_to_flow) {
            if (flow->mark == mark && flow->pmd_id == pmd->core_id &&
                flow->dead == false) {
                return flow;
            }
        }
    }

    return NULL;
}

static struct rte_offload_thread_item *
dpif_offload_rte_alloc_flow_offload(struct dp_netdev *dp,
                                    struct dp_netdev_flow *flow,
                                    int op)
{
    struct rte_offload_thread_item *item;
    struct rte_offload_flow_item *flow_offload;

    item = xzalloc(sizeof *item + sizeof *flow_offload);
    flow_offload = &item->data->flow;

    item->type = RTE_OFFLOAD_FLOW;
    item->dp = dp;

    flow_offload->flow = flow;
    flow_offload->op = op;

    dp_netdev_flow_ref(flow);

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
    struct rte_offload_flow_item *flow_offload = &offload->data->flow;

    dp_netdev_flow_unref(flow_offload->flow);
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
dpif_offload_rte_append_offload(struct rte_offload_thread_item *offload,
                                unsigned int tid)
{
    ovs_assert(offload_threads);

    mpsc_queue_insert(&offload_threads[tid].queue, &offload->node);
    atomic_count_inc64(&offload_threads[tid].enqueued_item);
}

static void
dpif_offload_rte_offload_flow_enqueue(struct rte_offload_thread_item *item)
{
    struct rte_offload_flow_item *flow_offload = &item->data->flow;
    unsigned int tid;

    ovs_assert(item->type == RTE_OFFLOAD_FLOW);

    if (flow_offload->flow) {
        tid = dpif_offload_rte_ufid_to_thread_id(flow_offload->flow->mega_ufid);
    } else {
        tid = dpif_offload_rte_ufid_to_thread_id(flow_offload->ufid);
    }
    dpif_offload_rte_append_offload(item, tid);
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

    netdev = dpif_offload_rte_flow_get_netdev(&thread->offload->offload,
                                              flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    error = netdev_offload_dpdk_flow_del(netdev, &flow->ufid,
                                         flow->requested_stats ? &stats
                                                               : NULL);

    mark = megaflow_to_mark_disassociate(&flow->ufid);

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
    struct dpif_netdev_offload_info info;
    struct dpif_flow_stats stats;
    struct netdev *netdev;
    uint32_t mark;
    int error = 0;

    mark = megaflow_to_mark_find(&flow->ufid);
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

    netdev = dpif_offload_rte_flow_get_netdev(&thread->offload->offload,
                                              flow->in_port);

    if (!netdev) {
        VLOG_DBG("Failed to find netdev for port_id %d", flow->in_port);
        error = ENODEV;
        goto do_callback;
    }

    info.flow_mark = mark;
    info.orig_in_port = flow->orig_in_port;

    error = netdev_offload_dpdk_flow_put(
        netdev, &flow->match, CONST_CAST(struct nlattr *, flow->actions),
        flow->actions_len, &flow->ufid, &info,
        flow->requested_stats ? &stats : NULL);

do_callback:
    if (!error && !modify) {
        megaflow_to_mark_associate(&flow->ufid, mark);
    } else if (error) {
        if (modify) {
            /* We failed the modification, so the flow is no longer
             * installed, remove the mapping. */
            megaflow_to_mark_disassociate(&flow->ufid);
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
             UUID_ARGS((struct uuid *) &flow_offload->flow->mega_ufid));
}

static void
dpif_offload_rte_offload_flush(struct rte_offload_thread_item *item)
{
    struct rte_offload_flush_item *flush = &item->data->flush;

    //XXX: ovs_rwlock_rdlock(&item->dp->port_rwlock);
    netdev_offload_dpdk_flow_flush(flush->netdev);
    //XXX: ovs_rwlock_unlock(&item->dp->port_rwlock);

    ovs_barrier_block(flush->barrier);

    /* Allow the initiator thread to take again the port lock,
     * before continuing offload operations in this thread.
     */
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

    queue = &ofl_thread->queue;
    mpsc_queue_acquire(queue);

    while (true) {
        backoff = RTE_OFFLOAD_BACKOFF_MIN;
        while (mpsc_queue_tail(queue) == NULL) {
            xnanosleep(backoff * 1E6);
            if (backoff < RTE_OFFLOAD_BACKOFF_MAX) {
                backoff <<= 1;
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
    }

    OVS_NOT_REACHED();
    mpsc_queue_release(queue);
}

static void
dpif_offload_rte_offload_threads_init(struct dpif_offload_rte_flow *offload)
{
    long long int now = time_usec();

    // offload->offload_threads = xcalloc(offload->offload_thread_count,
    offload_threads = xcalloc(offload->offload_thread_count,
                              sizeof(struct rte_offload_thread));

    for (unsigned int tid = 0; tid < offload->offload_thread_count; tid++) {
        struct rte_offload_thread *thread;

        //thread = &offload->offload_threads[tid];
        thread = &offload_threads[tid];
        mpsc_queue_init(&thread->queue);
        cmap_init(&thread->megaflow_to_mark);
        cmap_init(&thread->mark_to_flow);
        atomic_init(&thread->enqueued_item, 0);
        mov_avg_cma_init(&thread->cma);
        mov_avg_ema_init(&thread->ema, 100);
        atomic_store_relaxed(&thread->time_now, now);
        thread->offload = offload;
        ovs_thread_create("rte_offload", dpif_offload_rte_offload_thread_main,
                          thread);
    }
}

static long long int
dpif_offload_rte_get_thread_timestamp(const ovs_u128 *ufid)
{
    unsigned int tid = dpif_offload_rte_ufid_to_thread_id(*ufid);
    long long int time_now;

    atomic_read_relaxed(&offload_threads[tid].time_now, &time_now);
    return time_now;
}

//xxx: External declaration for cleanup
void dpif_offload_rte_flush(struct dp_netdev *, struct netdev *);
int dpif_offload_rte_stats_get(struct dpif *, struct netdev_custom_stats *);
int dpif_offload_rte_partial_offload_hw_flow(
    const struct dp_netdev_pmd_thread *, struct dp_packet *,
    struct dp_netdev_flow **);
bool dpif_offload_rte_get_flow_offload_status(const struct dp_netdev *,
                                              struct dp_netdev_flow *,
                                              struct dpif_flow_stats *,
                                              struct dpif_flow_attrs *);



static void
dpif_offload_rte_flush_enqueue(struct dp_netdev *dp,
                               struct netdev *netdev,
                               struct ovs_barrier *barrier)
{
    //XXX: This function, and dp_netdev_offload_flush() need to be
    //     migrated into port management in the new API, i.e.
    //     dpif_offload_rte_port_del().
    unsigned int tid;
    long long int now_us = time_usec();

    if (!dpif_offload_is_offload_enabled()) {
        return;
    }

    for (tid = 0; tid < rte_offload_thread_count; tid++) {
        struct rte_offload_thread_item *item;
        struct rte_offload_flush_item *flush;

        item = xmalloc(sizeof *item + sizeof *flush);
        item->type = RTE_OFFLOAD_FLUSH;
        item->dp = dp;
        item->timestamp = now_us;

        flush = &item->data->flush;
        flush->netdev = netdev;
        flush->barrier = barrier;

        dpif_offload_rte_append_offload(item, tid);
    }
}

/* Blocking call that will wait on the offload thread to
 * complete its work.  As the flush order will only be
 * enqueued after existing offload requests, those previous
 * offload requests must be processed, which requires being
 * able to lock the 'port_rwlock' from the offload thread.
 *
 * Flow offload flush is done when a port is being deleted.
 * Right after this call executes, the offload API is disabled
 * for the port. This call must be made blocking until the
 * offload provider completed its job.
 */
void
dpif_offload_rte_flush(struct dp_netdev *dp, struct netdev *netdev)
//XXX:    OVS_REQ_WRLOCK(dp->port_rwlock)
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
    ;

    if (!offload_threads) {
        // XXX: quit as this is probably called in a dummy datapath, without
        //      this offload even being enabled.
        netdev_close(netdev);
        return;
    }

    if (!dpif_offload_is_offload_enabled()) {
        netdev_close(netdev);
        return;
    }

    //XXX: ovs_rwlock_unlock(&dp->port_rwlock);
    ovs_mutex_lock(&flush_mutex);

    /* This thread and the offload threads. */
    ovs_barrier_init(&barrier, 1 + rte_offload_thread_count);

    dpif_offload_rte_flush_enqueue(dp, netdev, &barrier);
    ovs_barrier_block(&barrier);
    netdev_close(netdev);

    /* Take back the datapath port lock before allowing the offload
     * threads to proceed further. The port deletion must complete first,
     * to ensure no further offloads are inserted after the flush.
     *
     * Some offload provider (e.g. DPDK) keeps a netdev reference with
     * the offload data. If this reference is not closed, the netdev is
     * kept indefinitely. */
    //XXX: ovs_rwlock_wrlock(&dp->port_rwlock);

    ovs_barrier_block(&barrier);
    ovs_barrier_destroy(&barrier);

    ovs_mutex_unlock(&flush_mutex);
}

int
dpif_offload_rte_stats_get(struct dpif *dpif,
                           struct netdev_custom_stats *stats)
{
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

    unsigned int nb_thread = rte_offload_thread_count;
    unsigned int tid;
    size_t i;

    if (!dpif_offload_is_offload_enabled()) {
        return EINVAL;
    }

    if (!nb_thread) {
        return EINVAL;
    }

    /* nb_thread counters for the overall total as well. */
    stats->size = ARRAY_SIZE(hwol_stats) * (nb_thread + 1);
    stats->counters = xcalloc(stats->size, sizeof *stats->counters);

    for (tid = 0; tid < nb_thread; tid++) {
        uint64_t counts[ARRAY_SIZE(hwol_stats)];
        size_t idx = ((tid + 1) * ARRAY_SIZE(hwol_stats));

        memset(counts, 0, sizeof counts);
        if (offload_threads != NULL) {
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
        dpif_offload_flow_get_n_offloaded(dpif);

    for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
        snprintf(stats->counters[i].name, sizeof(stats->counters[i].name),
                 "  Total %s", hwol_stats[i].name);
        stats->counters[i].value = hwol_stats[i].total;
    }

    return 0;
}

bool
dpif_offload_rte_get_flow_offload_status(const struct dp_netdev *dp OVS_UNUSED,
                                         struct dp_netdev_flow *netdev_flow,
                                         struct dpif_flow_stats *stats,
                                         struct dpif_flow_attrs *attrs)
{
    uint64_t act_buf[1024 / 8];
    struct nlattr *actions;
    struct netdev *netdev;
    struct match match;
    struct ofpbuf buf;

    int ret = 0;

    if (!dpif_offload_is_offload_enabled()) {
        return false;
    }

    netdev = dpif_netdev_offload_get_netdev_by_port_id(
        netdev_flow->flow.in_port.odp_port);
    if (!netdev) {
        return false;
    }
    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);
    /* Taking a global 'port_rwlock' to fulfill thread safety
     * restrictions regarding netdev port mapping.
     *
     * XXX: Main thread will try to pause/stop all revalidators during datapath
     *      reconfiguration via datapath purge callback (dp_purge_cb) while
     *      rw-holding 'dp->port_rwlock'.  So we're not waiting for lock here.
     *      Otherwise, deadlock is possible, because revalidators might sleep
     *      waiting for the main thread to release the lock and main thread
     *      will wait for them to stop processing.
     *      This workaround might make statistics less accurate. Especially
     *      for flow deletion case, since there will be no other attempt.  */
/*     if (!ovs_rwlock_tryrdlock(&dp->port_rwlock)) { */
       ret = netdev_offload_dpdk_flow_get(netdev, &match, &actions,
                                          &netdev_flow->mega_ufid, stats,
                                          attrs, &buf);
        /* Storing statistics and attributes from the last request for
         * later use on mutex contention. */
/*         dp_netdev_flow_set_last_stats_attrs(netdev_flow, stats, attrs, ret);
        ovs_rwlock_unlock(&dp->port_rwlock);
    } else {
        dp_netdev_flow_get_last_stats_attrs(netdev_flow, stats, attrs, &ret);
        if (!ret && !attrs->dp_layer) { */
            /* Flow was never reported as 'offloaded' so it's harmless
             * to continue to think so. */
/*            ret = EAGAIN;
        }
    }
 */
    if (ret) {
        return false;
    }

    return true;
}


int
dpif_offload_rte_partial_offload_hw_flow(
    const struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet,
    struct dp_netdev_flow **flow)
{
    uint32_t mark;

#ifdef ALLOW_EXPERIMENTAL_API /* Packet restoration API required. */
    /* Restore the packet if HW processing was terminated before completion. */
    struct dp_netdev_rxq *rxq = pmd->ctx.last_rxq;
    bool miss_api_supported;

    atomic_read_relaxed(&rxq->port->netdev->hw_info.miss_api_supported,
                        &miss_api_supported);
    if (miss_api_supported) {
        int err = dpif_offload_netdev_hw_miss_packet_recover(rxq->port->netdev,
                                                             packet);
        if (err && err != EOPNOTSUPP) {
            COVERAGE_INC(datapath_drop_hw_miss_recover);
            return -1;
        }
    }
#endif

    /* If no mark, no flow to find. */
    if (!dp_packet_has_flow_mark(packet, &mark)) {
        *flow = NULL;
        return 0;
    }

    *flow = mark_to_flow_find(pmd, mark);
    return 0;
}


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
    struct netdev *netdev = port->netdev;

    netdev_offload_dpdk_init(netdev);
    dpif_offload_set_netdev_offload(netdev, dpif_offload);
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

static struct netdev *
dpif_offload_rte_flow_get_netdev(struct dpif_offload *offload,
                                 odp_port_t port_no)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);
    struct dpif_offload_port_mgr_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(offload_rte->port_mgr,
                                                  port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static int
dpif_offload_rte_open(const struct dpif_offload_class *offload_class,
         struct dpif *dpif, struct dpif_offload **dpif_offload) {
    struct dpif_offload_rte_flow *offload_rte;

    offload_rte = xmalloc(sizeof(struct dpif_offload_rte_flow));

    dpif_offload_init(&offload_rte->offload, offload_class, dpif);
    offload_rte->port_mgr = dpif_offload_port_mgr_init();
    offload_rte->once_enable = (struct ovsthread_once)
        OVSTHREAD_ONCE_INITIALIZER;

    *dpif_offload = &offload_rte->offload;
    offload_rte->offload_thread_count = DEFAULT_OFFLOAD_THREAD_COUNT;
    offload_rte->offload_threads = NULL;

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


            rte_offload_thread_count = offload_thread_count;

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

static bool
dpif_offload_rte_flow_get_n_offloaded_cb(
    struct dpif_offload_port_mgr_port *port, void *aux)
{
    uint64_t *total = aux;

    *total += netdev_offload_dpdk_flow_get_n_offloaded(port->netdev);
    return false;
}

static uint64_t
dpif_offload_rte_flow_get_n_offloaded(const struct dpif_offload *offload)
{
    struct dpif_offload_rte_flow *offload_rte = dpif_offload_rte_cast(offload);
    uint64_t total = 0;

    if (!dpif_offload_is_offload_enabled()) {
        return 0;
    }

    dpif_offload_port_mgr_traverse_ports(
        offload_rte->port_mgr, dpif_offload_rte_flow_get_n_offloaded_cb,
        &total);

    return total;
}

static int
dpif_offload_rte_netdev_flow_flush(const struct dpif_offload *offload
                                   OVS_UNUSED, struct netdev *netdev)
{
    return netdev_offload_dpdk_flow_flush(netdev);
}

static int
dpif_offload_rte_netdev_hw_miss_packet_recover(
    const struct dpif_offload *offload OVS_UNUSED, struct netdev *netdev,
    struct dp_packet *packet)
{
    return netdev_offload_dpdk_hw_miss_packet_recover(netdev, packet);
}

static int
dpif_offload_rte_netdev_flow_put(const struct dpif_offload *offload OVS_UNUSED,
                                 struct netdev *netdev OVS_UNUSED,
                                 struct dpif_offload_flow_put *put,
                                 uint32_t *flow_mark)
{
    struct rte_offload_thread_item *item;
    struct rte_offload_flow_item *flow_offload;

    //XXXX: FIXME IGNORE CALL FOR TESTING PURPOSE...
//    return 0;

    item = dpif_offload_rte_alloc_flow_offload(
        NULL, NULL, put->modify ? RTE_NETDEV_FLOW_OFFLOAD_OP_MOD
                                : RTE_NETDEV_FLOW_OFFLOAD_OP_ADD);

    flow_offload = &item->data->flow;
    flow_offload->in_port = put->in_port;
    flow_offload->ufid = *put->ufid;
    flow_offload->match = *put->match;
    flow_offload->actions = xmalloc(put->actions_len);
    memcpy(flow_offload->actions, put->actions, put->actions_len);
    flow_offload->actions_len = put->actions_len;
    flow_offload->orig_in_port = put->orig_in_port;
    flow_offload->requested_stats = !!put->stats;
    flow_offload->callback = put->cb_data;

    item->timestamp = dpif_offload_rte_get_thread_timestamp(put->ufid);
    dpif_offload_rte_offload_flow_enqueue(item);

    *flow_mark = INVALID_FLOW_MARK;
    return EINPROGRESS;
}

static int
dpif_offload_rte_netdev_flow_del(const struct dpif_offload *offload OVS_UNUSED,
                                 struct netdev *netdev OVS_UNUSED,
                                 struct dpif_offload_flow_del *del,
                                 uint32_t *flow_mark)
{
    struct rte_offload_thread_item *item;
    struct rte_offload_flow_item *flow_offload;

    // XXXX: FIXME IGNORE CALL FOR TESTING PURPOSE...
    //return 0;

    item = dpif_offload_rte_alloc_flow_offload(
        NULL, NULL, RTE_NETDEV_FLOW_OFFLOAD_OP_DEL);

    flow_offload = &item->data->flow;
    flow_offload->in_port = del->in_port;
    flow_offload->requested_stats = !!del->stats;
    flow_offload->ufid = *del->ufid;
    flow_offload->callback = del->cb_data;

    item->timestamp = dpif_offload_rte_get_thread_timestamp(del->ufid);
    dpif_offload_rte_offload_flow_enqueue(item);

    *flow_mark = INVALID_FLOW_MARK;
    return EINPROGRESS;
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
    .can_offload = dpif_offload_rte_can_offload,
    .port_add = dpif_offload_rte_port_add,
    .port_del = dpif_offload_rte_port_del,
    .port_dump_start = dpif_offload_rte_port_dump_start,
    .port_dump_next = dpif_offload_rte_port_dump_next,
    .port_dump_done = dpif_offload_rte_port_dump_done,
    .flow_get_n_offloaded = dpif_offload_rte_flow_get_n_offloaded,
    .get_netdev = dpif_offload_rte_flow_get_netdev,
    .netdev_flow_flush = dpif_offload_rte_netdev_flow_flush,
    .netdev_hw_miss_packet_recover = \
        dpif_offload_rte_netdev_hw_miss_packet_recover,
    .netdev_flow_put = dpif_offload_rte_netdev_flow_put,
    .netdev_flow_del = dpif_offload_rte_netdev_flow_del,
};

/* XXX: Remove once hw-offload is fully separated from dpif-netdev. */
unsigned int dpif_offload_rte_offload_thread_count(void);

unsigned int dpif_offload_rte_offload_thread_count(void)
{
    return rte_offload_thread_count;
}
