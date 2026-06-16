
#!/usr/bin/env python3
#
# Copyright (c) 2026 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# HACKED TOGETHER WITH: OpenCode and Claude Opus 4.6
#
# Script information:
# -------------------
# This script allows a developer to quickly get statistics around hmap
# usage for the supplied PID.
#
#   - hmap_init()             (uprobe) tracks each hmap instance's lifetime.
#   - hmap:insert             (USDT)   records the exact peak entry count.
#   - hmap:first / hmap:next  (USDT)   tracks full-table iteration depth.
#   - hmap:first_with_hash /  (USDT)   tracks hash-bucket lookup depth.
#     hmap:next_with_hash
#
# On exit a max-size summary table is printed (one row per hmap instance),
# followed by iteration histograms (full scan and hash lookup) for the
# top N largest hmaps.
#
# All USDT probes require OVS to have been built with --enable-usdt-probes
# and the corresponding OVS_USDT_PROBE() calls in hmap.h.
#
#
# Dependencies:
# -------------
#  You need to install the BCC package for your specific platform or build it
#  yourself using the following instructions:
#    https://raw.githubusercontent.com/iovisor/bcc/master/INSTALL.md
#
#  Python needs the following additional packages installed:
#    - psutil
#
#  You can either install your distribution specific package or use pip:
#    pip install psutil
#
import argparse
import io
import itertools
import os
import psutil
import re
import signal
import sys

try:
    from bcc import BPF, USDT, USDTException
except ModuleNotFoundError:
    print("ERROR: Can't find the BPF Compiler Collection (BCC) tools!")
    sys.exit(os.EX_OSFILE)


#
# Actual eBPF source code
#
EBPF_SOURCE = """
#include <uapi/linux/ptrace.h>

#define MONITOR_PID <MONITOR_PID>

enum {
    EVENT_HMAP_INIT             = 0,
    EVENT_HMAP_INSERT           = 1,
    EVENT_HMAP_QUERY_START      = 2,
    EVENT_HMAP_QUERY_END        = 3,
    EVENT_HMAP_HASH_QUERY_START = 4,
    EVENT_HMAP_HASH_QUERY_END   = 5,
};

struct event_t {
    u64 ts;
    u32 tid;
    u32 type;
    u64 hmap_ptr;
    u64 n;           /* hmap->n (insert: post-insert; query_start: at scan) */
    u64 iter_count;  /* query_end: number of next calls in this scan        */
    u64 caller;      /* return address from stack; init events only          */
};

BPF_RINGBUF_OUTPUT(events, <BUFFER_PAGE_CNT>);
BPF_TABLE("percpu_array", uint32_t, uint64_t, dropcnt, 1);

/*
 * Per-(hmap, tid) scan state for full-table iterations
 * (hmap_first / hmap_next).
 */
struct scan_key_t {
    u64 hmap_ptr;
    u32 tid;
};

BPF_HASH(scan_count,   struct scan_key_t, u64);
BPF_HASH(scan_start_n, struct scan_key_t, u64);

/*
 * Per-tid scan state for hash-bucket lookups
 * (hmap_first_with_hash / hmap_next_with_hash).
 *
 * Keyed on tid only because hmap_next_with_hash() does not receive the
 * hmap pointer — the hmap_ptr is stored from hmap_first_with_hash().
 */
BPF_HASH(hscan_count,   u32, u64);
BPF_HASH(hscan_start_n, u32, u64);
BPF_HASH(hscan_hmap,    u32, u64);

/* ------------------------------------------------------------------ */

int on_hmap_init(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if ((pid_tgid >> 32) != MONITOR_PID)
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) {
        dropcnt.increment(0);
        return 0;
    }

    u64 caller = 0;
    bpf_probe_read(&caller, sizeof(caller), (void *)PT_REGS_SP(ctx));

    e->ts         = bpf_ktime_get_ns();
    e->tid        = (u32)pid_tgid;
    e->type       = EVENT_HMAP_INIT;
    e->hmap_ptr   = PT_REGS_PARM1(ctx);
    e->n          = 0;
    e->iter_count = 0;
    e->caller     = caller;
    events.ringbuf_submit(e, 0);
    return 0;
}

/*
 * hmap:insert — fires after hmap->n++ in hmap_insert_fast().
 * arg1 = hmap *, arg2 = hmap->n post-insert.
 */
int on_hmap_insert(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if ((pid_tgid >> 32) != MONITOR_PID)
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) {
        dropcnt.increment(0);
        return 0;
    }

    u64 hmap_ptr = 0, n = 0;
    bpf_usdt_readarg(1, ctx, &hmap_ptr);
    bpf_usdt_readarg(2, ctx, &n);

    e->ts         = bpf_ktime_get_ns();
    e->tid        = (u32)pid_tgid;
    e->type       = EVENT_HMAP_INSERT;
    e->hmap_ptr   = hmap_ptr;
    e->n          = n;
    e->iter_count = 0;
    e->caller     = 0;
    events.ringbuf_submit(e, 0);
    return 0;
}

/* ---- full-table iteration: hmap_first / hmap_next ---- */

/*
 * hmap:first — marks the start of a full-table iteration.
 * arg1 = hmap *, arg2 = hmap->n.
 * Flushes any previous open scan on (hmap, tid).
 */
int on_hmap_first(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if ((pid_tgid >> 32) != MONITOR_PID)
        return 0;

    u64 hmap_ptr = 0, n = 0;
    bpf_usdt_readarg(1, ctx, &hmap_ptr);
    bpf_usdt_readarg(2, ctx, &n);

    u32 tid = (u32)pid_tgid;
    struct scan_key_t key = { .hmap_ptr = hmap_ptr, .tid = tid };

    /* Flush previous open scan on this (hmap, tid). */
    u64 *prev_count = scan_count.lookup(&key);
    if (prev_count) {
        u64 *prev_n = scan_start_n.lookup(&key);
        struct event_t *end = events.ringbuf_reserve(sizeof(*end));
        if (end) {
            end->ts         = bpf_ktime_get_ns();
            end->tid        = tid;
            end->type       = EVENT_HMAP_QUERY_END;
            end->hmap_ptr   = hmap_ptr;
            end->n          = prev_n ? *prev_n : 0;
            end->iter_count = *prev_count;
            end->caller     = 0;
            events.ringbuf_submit(end, 0);
        } else {
            dropcnt.increment(0);
        }
    }

    /* Start new scan. */
    u64 zero = 0;
    scan_count.update(&key, &zero);
    scan_start_n.update(&key, &n);

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) {
        dropcnt.increment(0);
        return 0;
    }

    e->ts         = bpf_ktime_get_ns();
    e->tid        = tid;
    e->type       = EVENT_HMAP_QUERY_START;
    e->hmap_ptr   = hmap_ptr;
    e->n          = n;
    e->iter_count = 0;
    e->caller     = 0;
    events.ringbuf_submit(e, 0);
    return 0;
}

/*
 * hmap:next — counts one iteration step.
 * arg1 = hmap *.  No event emitted.
 */
int on_hmap_next(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if ((pid_tgid >> 32) != MONITOR_PID)
        return 0;

    u64 hmap_ptr = 0;
    bpf_usdt_readarg(1, ctx, &hmap_ptr);

    u32 tid = (u32)pid_tgid;
    struct scan_key_t key = { .hmap_ptr = hmap_ptr, .tid = tid };

    u64 *count = scan_count.lookup(&key);
    if (count)
        (*count)++;

    return 0;
}

/* ---- hash-bucket lookup: hmap_first_with_hash / hmap_next_with_hash ---- */

/*
 * hmap:first_with_hash — marks the start of a hash-bucket lookup.
 * arg1 = hmap *, arg2 = hmap->n.
 * Keyed on tid only (hmap_next_with_hash has no hmap *).
 * Flushes any previous open hash scan on this tid.
 */
int on_hmap_first_with_hash(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if ((pid_tgid >> 32) != MONITOR_PID)
        return 0;

    u64 hmap_ptr = 0, n = 0;
    bpf_usdt_readarg(1, ctx, &hmap_ptr);
    bpf_usdt_readarg(2, ctx, &n);

    u32 tid = (u32)pid_tgid;

    /* Flush previous open hash scan on this tid. */
    u64 *prev_count = hscan_count.lookup(&tid);
    if (prev_count) {
        u64 *prev_hmap = hscan_hmap.lookup(&tid);
        u64 *prev_n    = hscan_start_n.lookup(&tid);
        struct event_t *end = events.ringbuf_reserve(sizeof(*end));
        if (end) {
            end->ts         = bpf_ktime_get_ns();
            end->tid        = tid;
            end->type       = EVENT_HMAP_HASH_QUERY_END;
            end->hmap_ptr   = prev_hmap ? *prev_hmap : 0;
            end->n          = prev_n ? *prev_n : 0;
            end->iter_count = *prev_count;
            end->caller     = 0;
            events.ringbuf_submit(end, 0);
        } else {
            dropcnt.increment(0);
        }
    }

    /* Start new hash scan. */
    u64 zero = 0;
    hscan_count.update(&tid, &zero);
    hscan_start_n.update(&tid, &n);
    hscan_hmap.update(&tid, &hmap_ptr);

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) {
        dropcnt.increment(0);
        return 0;
    }

    e->ts         = bpf_ktime_get_ns();
    e->tid        = tid;
    e->type       = EVENT_HMAP_HASH_QUERY_START;
    e->hmap_ptr   = hmap_ptr;
    e->n          = n;
    e->iter_count = 0;
    e->caller     = 0;
    events.ringbuf_submit(e, 0);
    return 0;
}

/*
 * hmap:next_with_hash — counts one hash-bucket lookup step.
 * No args needed — keyed on tid, counter incremented.
 * No event emitted.
 */
int on_hmap_next_with_hash(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if ((pid_tgid >> 32) != MONITOR_PID)
        return 0;

    u32 tid = (u32)pid_tgid;

    u64 *count = hscan_count.lookup(&tid);
    if (count)
        (*count)++;

    return 0;
}
"""


#
# next_power_of_two()
#
def next_power_of_two(val):
    np = 1
    while np < val:
        np *= 2
    return np


#
# unsigned_int()
#
def unsigned_int(value):
    try:
        value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if value < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


#
# get_thread_name()
#
def get_thread_name(pid, tid):
    try:
        with open(f"/proc/{pid}/task/{tid}/comm", encoding="utf8") as f:
            return f.readline().strip("\n")
    except FileNotFoundError:
        pass

    return f"<unknown:{pid}/{tid}>"


#
# Event type constants (must match the eBPF enum).
#
EVENT_HMAP_INIT             = 0
EVENT_HMAP_INSERT           = 1
EVENT_HMAP_QUERY_START      = 2
EVENT_HMAP_QUERY_END        = 3
EVENT_HMAP_HASH_QUERY_START = 4
EVENT_HMAP_HASH_QUERY_END   = 5


#
# active_hmaps    — keyed on hmap_ptr, tracks the current live instance.
# completed_hmaps — finalized records (address reused or tracing ended).
# pending_scans   — open full-table scans: {(hmap_ptr, tid) -> {n_at_start}}
# pending_hscans  — open hash-bucket scans: {tid -> {hmap_ptr, n_at_start}}
#
active_hmaps    = {}
completed_hmaps = []
pending_scans   = {}
pending_hscans  = {}


#
# resolve_caller()
#
def resolve_caller(addr):
    if addr == 0:
        return "<unknown>"
    sym = bpf.sym(addr, options.pid,
                  show_module=True, show_offset=True)
    return sym.decode("utf-8", "replace")


#
# new_hmap_entry()
#
def new_hmap_entry(ts, caller):
    return {"init_ts":             ts,
            "caller":              caller,
            "max_n":               0,
            # Full-table iteration stats (hmap_first / hmap_next)
            "query_count":         0,
            "query_iter_min":      None,
            "query_iter_max":      0,
            "query_iter_sum":      0,
            "query_n_min":         None,
            "query_n_max":         0,
            "query_iter_hist":     {},
            # Hash-bucket lookup stats (hmap_first_with_hash / next_with_hash)
            "hash_query_count":    0,
            "hash_iter_min":       None,
            "hash_iter_max":       0,
            "hash_iter_sum":       0,
            "hash_n_min":          None,
            "hash_n_max":          0,
            "hash_iter_hist":      {}}


#
# record_scan() — record a completed full-table iteration.
#
def record_scan(hmap_ptr, iter_count, n_at_start):
    if hmap_ptr not in active_hmaps:
        return

    info = active_hmaps[hmap_ptr]
    info["query_count"] += 1
    info["query_iter_sum"] += iter_count
    info["query_iter_max"] = max(info["query_iter_max"], iter_count)
    info["query_iter_min"] = iter_count if info["query_iter_min"] is None \
                             else min(info["query_iter_min"], iter_count)
    info["query_n_max"] = max(info["query_n_max"], n_at_start)
    info["query_n_min"] = n_at_start if info["query_n_min"] is None \
                          else min(info["query_n_min"], n_at_start)
    info["query_iter_hist"][iter_count] = \
        info["query_iter_hist"].get(iter_count, 0) + 1


#
# record_hash_scan() — record a completed hash-bucket lookup.
#
def record_hash_scan(hmap_ptr, iter_count, n_at_start):
    if hmap_ptr not in active_hmaps:
        return

    info = active_hmaps[hmap_ptr]
    info["hash_query_count"] += 1
    info["hash_iter_sum"] += iter_count
    info["hash_iter_max"] = max(info["hash_iter_max"], iter_count)
    info["hash_iter_min"] = iter_count if info["hash_iter_min"] is None \
                            else min(info["hash_iter_min"], iter_count)
    info["hash_n_max"] = max(info["hash_n_max"], n_at_start)
    info["hash_n_min"] = n_at_start if info["hash_n_min"] is None \
                         else min(info["hash_n_min"], n_at_start)
    info["hash_iter_hist"][iter_count] = \
        info["hash_iter_hist"].get(iter_count, 0) + 1


#
# flush_scans_for_hmap()
#
def flush_scans_for_hmap(hmap_ptr):
    to_remove = [k for k in pending_scans if k[0] == hmap_ptr]
    for k in to_remove:
        del pending_scans[k]

    to_remove = [k for k, v in pending_hscans.items()
                 if v["hmap_ptr"] == hmap_ptr]
    for k in to_remove:
        del pending_hscans[k]


#
# process_event()
#
def process_event(ctx, data, size):
    event    = bpf["events"].event(data)
    hmap_ptr = event.hmap_ptr

    if event.type == EVENT_HMAP_INIT:
        caller = resolve_caller(event.caller)

        if hmap_ptr in active_hmaps:
            flush_scans_for_hmap(hmap_ptr)
            completed_hmaps.append({"hmap_ptr": hmap_ptr,
                                    **active_hmaps[hmap_ptr]})

        active_hmaps[hmap_ptr] = new_hmap_entry(event.ts, caller)

    elif event.type == EVENT_HMAP_INSERT:
        if hmap_ptr in active_hmaps:
            if event.n > active_hmaps[hmap_ptr]["max_n"]:
                active_hmaps[hmap_ptr]["max_n"] = event.n

    # ---- full-table iteration events ----

    elif event.type == EVENT_HMAP_QUERY_START:
        pending_scans[(hmap_ptr, event.tid)] = {"n_at_start": event.n}

    elif event.type == EVENT_HMAP_QUERY_END:
        scan_key = (hmap_ptr, event.tid)
        n_at_start = event.n

        if scan_key in pending_scans:
            n_at_start = pending_scans[scan_key]["n_at_start"]
            del pending_scans[scan_key]

        record_scan(hmap_ptr, event.iter_count, n_at_start)

    # ---- hash-bucket lookup events ----

    elif event.type == EVENT_HMAP_HASH_QUERY_START:
        pending_hscans[event.tid] = {"hmap_ptr":   hmap_ptr,
                                     "n_at_start": event.n}

    elif event.type == EVENT_HMAP_HASH_QUERY_END:
        n_at_start = event.n

        if event.tid in pending_hscans:
            n_at_start = pending_hscans[event.tid]["n_at_start"]
            hmap_ptr   = pending_hscans[event.tid]["hmap_ptr"]
            del pending_hscans[event.tid]

        record_hash_scan(hmap_ptr, event.iter_count, n_at_start)


#
# flush_open_scans()
#
def flush_open_scans():
    # Full-table scans
    try:
        sc = bpf["scan_count"]
        sn = bpf["scan_start_n"]
        for key, count_val in sc.items():
            n_at_start = 0
            try:
                n_at_start = sn[key].value
            except KeyError:
                pass
            record_scan(key.hmap_ptr, count_val.value, n_at_start)
    except KeyError:
        pass

    # Hash-bucket scans
    try:
        hc = bpf["hscan_count"]
        hn = bpf["hscan_start_n"]
        hh = bpf["hscan_hmap"]
        for tid_key, count_val in hc.items():
            hmap_ptr = 0
            n_at_start = 0
            try:
                hmap_ptr = hh[tid_key].value
            except KeyError:
                pass
            try:
                n_at_start = hn[tid_key].value
            except KeyError:
                pass
            record_hash_scan(hmap_ptr, count_val.value, n_at_start)
    except KeyError:
        pass


#
# hist_buckets()
#
def hist_buckets(hist):
    if not hist:
        return []

    max_val = max(hist.keys())

    buckets = []
    k = 0
    while True:
        if k == 0:
            lo, hi = 0, 0
            label = "         0"
        elif k == 1:
            lo, hi = 1, 1
            label = "         1"
        else:
            lo = 1 << (k - 1)
            hi = (1 << k) - 1
            label = "{:5d}-{:<5d}".format(lo, hi)

        count = sum(v for n, v in hist.items() if lo <= n <= hi)
        buckets.append((label, count))

        if hi >= max_val:
            break

        k += 1

    return buckets


BAR_WIDTH = 40


#
# write_histogram() — write one histogram block to a StringIO buffer.
#
def write_histogram(rec, hist_key, count_key, iter_min_key, iter_max_key,
                    iter_sum_key, n_min_key, n_max_key, title, f):
    buckets = hist_buckets(rec[hist_key])
    if not buckets:
        return

    qc   = rec[count_key]
    imin = rec[iter_min_key] if rec[iter_min_key] is not None else 0
    imax = rec[iter_max_key]
    iavg = rec[iter_sum_key] / qc if qc else 0
    nmin = rec[n_min_key] if rec[n_min_key] is not None else 0
    nmax = rec[n_max_key]

    f.write("# [{}]  hmap=0x{:016x}  init={:<22d}  max_n={:d}\n".format(
        title, rec["hmap_ptr"], rec["init_ts"], rec["max_n"]))
    f.write("# caller={}\n".format(rec["caller"]))
    f.write("# queries={:d}  iter: min={:d}  max={:d}  avg={:.1f}\n".format(
        qc, imin, imax, iavg))
    f.write("#               size: min={:d}  max={:d}\n".format(nmin, nmax))
    f.write("#\n")

    max_count = max(c for _, c in buckets) or 1
    f.write("  {:<16}  {:>8}  {}\n".format(
        "ITERATIONS", "COUNT", "DISTRIBUTION"))
    f.write("  {:<16}  {:>8}  {}\n".format(
        "-" * 16, "-" * 8, "-" * BAR_WIDTH))

    for label, count in buckets:
        bar = "#" * int(BAR_WIDTH * count / max_count) if count else ""
        f.write("  {:<16}  {:>8d}  {}\n".format(label, count, bar))

    f.write("\n")


#
# print_summary()
#
def print_summary():
    f = io.StringIO()

    # Merge any still-active instances into the completed list.
    for ptr, info in active_hmaps.items():
        completed_hmaps.append({"hmap_ptr": ptr, **info})

    if not completed_hmaps:
        f.write("\n# No hmap instances recorded.\n")
        os.write(1, f.getvalue().encode())
        os._exit(0)

    n_active    = len(active_hmaps)
    n_completed = len(completed_hmaps) - n_active

    # ------------------------------------------------------------------
    # Section 1 — max-size table (all instances, sorted by max_n desc).
    # ------------------------------------------------------------------
    by_max_n = sorted(completed_hmaps, key=lambda x: x["max_n"],
                      reverse=True)

    f.write("\n# HMAP MAX SIZE SUMMARY (sorted by max size):\n#\n")
    f.write("  {:<18}  {:<22}  {:>8}  {}\n".format(
        "HMAP ADDRESS", "INIT TIMESTAMP (ns)", "MAX SIZE", "INIT CALLER"))
    f.write("  {:<18}  {:<22}  {:>8}  {}\n".format(
        "-" * 18, "-" * 22, "-" * 8, "-" * 48))

    for rec in by_max_n:
        f.write("  0x{:<16x}  {:<22d}  {:>8d}  {}\n".format(
            rec["hmap_ptr"], rec["init_ts"], rec["max_n"], rec["caller"]))

    f.write("\n# Total instances seen: {}  "
            "({} still active at exit, {} completed)\n".format(
                len(completed_hmaps), n_active, n_completed))

    # ------------------------------------------------------------------
    # Section 2 — full-table iteration histograms.
    # ------------------------------------------------------------------
    queried = [r for r in completed_hmaps if r["query_count"] > 0]
    limit   = options.histogram_count

    if queried:
        queried.sort(key=lambda x: x["max_n"], reverse=True)
        shown = queried if limit == 0 else queried[:limit]

        f.write("\n\n# FULL-TABLE ITERATION HISTOGRAMS "
                "(top {} of {} hmaps, sorted by max size):\n#\n".format(
                    len(shown), len(queried)))

        for rec in shown:
            write_histogram(rec,
                            "query_iter_hist", "query_count",
                            "query_iter_min", "query_iter_max",
                            "query_iter_sum",
                            "query_n_min", "query_n_max",
                            "FULL SCAN", f)
    else:
        f.write("\n# No full-table iteration data recorded.\n")

    # ------------------------------------------------------------------
    # Section 3 — hash-bucket lookup histograms.
    # ------------------------------------------------------------------
    hqueried = [r for r in completed_hmaps if r["hash_query_count"] > 0]

    if hqueried:
        hqueried.sort(key=lambda x: x["max_n"], reverse=True)
        hshown = hqueried if limit == 0 else hqueried[:limit]

        f.write("\n\n# HASH-BUCKET LOOKUP HISTOGRAMS "
                "(top {} of {} hmaps, sorted by max size):\n#\n".format(
                    len(hshown), len(hqueried)))

        for rec in hshown:
            write_histogram(rec,
                            "hash_iter_hist", "hash_query_count",
                            "hash_iter_min", "hash_iter_max",
                            "hash_iter_sum",
                            "hash_n_min", "hash_n_max",
                            "HASH LOOKUP", f)
    else:
        f.write("\n# No hash-bucket lookup data recorded.\n")

    f.write("\n# Detaching probes (this may take a while) ...\n")

    output = f.getvalue()

    if options.output:
        with open(options.output, "w") as out:
            out.write(output)
        try:
            print("# Output written to {}".format(options.output),
                  flush=True)
        except BrokenPipeError:
            pass
    else:
        try:
            sys.stdout.write(output)
            sys.stdout.flush()
        except BrokenPipeError:
            pass


#
# main()
#
def main():
    global bpf
    global options

    #
    # Argument parsing
    #
    parser = argparse.ArgumentParser()

    parser.add_argument("-D", "--debug",
                        help="Enable eBPF debugging",
                        type=int, const=0x3f, default=0, nargs="?")
    parser.add_argument("-p", "--pid", metavar="VSWITCHD_PID",
                        help="ovs-vswitchd's PID",
                        type=unsigned_int, default=None)
    parser.add_argument("--buffer-page-count",
                        help="Number of BPF ring buffer pages, default 1024",
                        type=unsigned_int, default=1024, metavar="NUMBER")
    parser.add_argument("--histogram-count",
                        help="Number of hmaps to show query histograms for, "
                        "sorted by max size descending. Default 5, "
                        "0 means show all.",
                        type=unsigned_int, default=5, metavar="NUMBER")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write summary output to FILE instead of stdout",
                        type=str, default=None)

    options = parser.parse_args()

    #
    # Find the PID of the ovs-vswitchd daemon if not specified.
    #
    if not options.pid:
        for proc in psutil.process_iter():
            if "ovs-vswitchd" in proc.name():
                if options.pid:
                    print("ERROR: Multiple ovs-vswitchd daemons running, "
                          "use the -p option!")
                    sys.exit(os.EX_NOINPUT)

                options.pid = proc.pid

    #
    # Error checking on input parameters.
    #
    if not options.pid:
        print("ERROR: Failed to find ovs-vswitchd's PID!")
        sys.exit(os.EX_UNAVAILABLE)

    options.buffer_page_count = next_power_of_two(options.buffer_page_count)

    #
    # Make sure we are running as root, or else we can not attach the probes.
    #
    if os.geteuid() != 0:
        print("ERROR: We need to run as root to attach probes!")
        sys.exit(os.EX_NOPERM)

    #
    # Substitute placeholders in the eBPF source.
    #
    source = EBPF_SOURCE.replace("<MONITOR_PID>", str(options.pid))
    source = source.replace("<BUFFER_PAGE_CNT>",
                            str(options.buffer_page_count))

    #
    # Set up the USDT probes.  All probes are defined in
    # include/openvswitch/hmap.h and require --enable-usdt-probes.
    #
    usdt = USDT(pid=int(options.pid))
    try:
        usdt.enable_probe(probe="insert",          fn_name="on_hmap_insert")
        usdt.enable_probe(probe="first",           fn_name="on_hmap_first")
        usdt.enable_probe(probe="next",            fn_name="on_hmap_next")
        usdt.enable_probe(probe="first_with_hash", fn_name="on_hmap_first_with_hash")
        usdt.enable_probe(probe="next_with_hash",  fn_name="on_hmap_next_with_hash")
    except USDTException as e:
        print("ERROR: {}".format(
            (re.sub("^", " " * 7, str(e), flags=re.MULTILINE)).strip().
            replace("--with-dtrace or --enable-dtrace",
                    "--enable-usdt-probes")))
        sys.exit(os.EX_OSERR)

    #
    # Raise the BCC probe limit.  The default (1000) is not enough for
    # the ~1200 USDT probe sites across hmap_insert, hmap_first,
    # hmap_next, hmap_first_with_hash, and hmap_next_with_hash.
    #
    os.environ.setdefault("BCC_PROBE_LIMIT", "4096")

    #
    # Raise the file descriptor limit.  Each USDT probe site requires
    # one open fd, and the default ulimit (1024) is too low for ~1200
    # probe sites.  We need root for this (already checked above).
    #
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < 8192:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, hard), hard))

    print("Loading BPF program and attaching probes "
          "(this may take a while) ...", flush=True)
    bpf = BPF(text=source, usdt_contexts=[usdt], debug=options.debug)

    #
    # Attach uprobe to hmap_init() in the vswitchd binary.
    #
    try:
        bpf.attach_uprobe(name=f"/proc/{options.pid}/exe",
                          sym="hmap_init",
                          fn_name="on_hmap_init",
                          pid=options.pid)
    except Exception as e:
        print(f"ERROR: Failed to attach uprobe to hmap_init(): {e}")
        sys.exit(os.EX_OSERR)

    #
    # Open the ring buffer and register the event callback.
    #
    bpf["events"].open_ring_buffer(process_event)

    #
    # Start polling.
    #
    print("Tracing hmap activity for PID {} ... Hit Ctrl-C to stop.".format(
        options.pid))

    spinner = itertools.cycle(r"|\-/")
    while True:
        try:
            bpf.ring_buffer_poll(timeout=100)
            try:
                print("\r[{}]".format(next(spinner)), end="", flush=True)
            except BrokenPipeError:
                break
        except KeyboardInterrupt:
            try:
                print(flush=True)
            except BrokenPipeError:
                pass
            break

    #
    # From this point on, ignore further Ctrl-C so shutdown completes.
    #
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    #
    # Flush any scans still open when tracing stopped.
    #
    flush_open_scans()

    #
    # Check for dropped events.
    #
    dropcnt = bpf.get_table("dropcnt")
    for k in dropcnt.keys():
        count = dropcnt.sum(k).value
        if k.value == 0 and count > 0:
            try:
                print("\n# WARNING: Not all events were captured, {} were "
                      "dropped!\n#          Increase the BPF ring buffer size "
                      "with the --buffer-page-count option.".format(count))
            except BrokenPipeError:
                pass

    #
    # Print summary and exit.
    #
    print_summary()


#
# Start main() as the default entry point...
#
if __name__ == "__main__":
    main()
