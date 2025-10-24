/* Copyright (c) 2025 Red Hat, Inc.
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
 * limitations under the License.  */

#ifndef EC_DEBUG_H
#define EC_DEBUG_H

/* USAGE NOTES:
 *  Use ./configure CFLAGS="-g -O2 -rdynamic ..." to add function names to the
 *  glibc backtraces, but it does not always work :(. The preferred mode is
 *  to make sure libunwind is present.
 */

#include <execinfo.h>
#include "backtrace.h"
#include "lib/util.h"

#define MB(x) ((x) * 1024 * 1024)
#define GB(x) ((x) * 1024 * 1024 * 1024)

#define EC_DEBUG_BUFFER_SIZE MB(512)

#define EC_TIME_STAMP ((EC_DEBUG_BUFFER_SIZE/256) - 10)

extern struct ec_debug_buffer EC_DEBUG_BUFFER;

struct ec_debug_buffer {
    size_t size;                         /* Total buffer size. */
    size_t start;                        /* Index of oldest byte. */
    size_t write;                        /* Next write index. */
    struct ovs_mutex mutex;
    uint8_t buffer[EC_DEBUG_BUFFER_SIZE];
};

static inline void
ec_dbg_add_buffer(const char *data, size_t len)
{
    /* Quick and dirty circular buffer with a lock. It has a counter wrap
     * issue if we write more than size_t bytes. Assuming size_t is 64-bits
     * this will not happen for a long time ;). */
    struct ec_debug_buffer *buf = &EC_DEBUG_BUFFER;
    size_t idx, first_part;

    if (len >= buf->size) {
        return;
    }

    ovs_mutex_lock(&buf->mutex);

    size_t free_space = buf->size - (buf->write - buf->start);
    if (len > free_space) {
        /* Advance start to make room for new data. */
        buf->start += len - free_space;
    }

    idx = buf->write % buf->size;
    first_part = len;
    if (idx + len > buf->size) {
        first_part = buf->size - idx;
    }

    memcpy(&buf->buffer[idx], data, first_part);
    if (len > first_part) {
        memcpy(&buf->buffer[0], data + first_part, len - first_part);
    }

    buf->write += len;
    ovs_mutex_unlock(&buf->mutex);
}

static inline void OVS_PRINTF_FORMAT (2, 3)
ec_dbg_at(const char *where, const char *message, ...)
{
    static atomic_count next_msg_id = ATOMIC_COUNT_INIT(0);
    int msg_id = atomic_count_inc(&next_msg_id);
    const char *thread = get_subprogram_name();
    long long int now = time_usec();
    char line_buffer[512];
    va_list args;
    int len = 0;

    if (!thread || thread[0] == 0) {
        thread = "main";
    }

    if (msg_id % EC_TIME_STAMP == 0) {
        char date_str[32];
        struct tm_msec tm;

        gmtime_msec(time_wall_msec(), &tm);
        strftime_msec(date_str, sizeof date_str, "%Y-%m-%d %H:%M:%S.###", &tm);
        snprintf(line_buffer, sizeof line_buffer, "%lld|%s|||: time: %s\n",
                           now, thread, date_str);
        ec_dbg_add_buffer(line_buffer, strlen(line_buffer));
    }

#ifdef HAVE_UNWIND
    /* We have lib unwind which is the best option ;) */
    struct unw_backtrace unw_bt[4];
    unw_cursor_t cursor;
    int stack_size = 0;
    unw_context_t uc;

    if (unw_getcontext(&uc) >= 0 && unw_init_local(&cursor, &uc) > 0) {
        while (stack_size < ARRAY_SIZE(unw_bt) && unw_step(&cursor) > 0) {
            memset(unw_bt[stack_size].func, 0, UNW_MAX_FUNCN);
            unw_get_reg(&cursor, UNW_REG_IP, &unw_bt[stack_size].ip);
            unw_get_proc_name(&cursor, unw_bt[stack_size].func, UNW_MAX_FUNCN,
                              &unw_bt[stack_size].offset);
            stack_size++;
        }
    }

    switch (stack_size) {
        case 4:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|"
                           "%s()[%lu]<-%s()[%lu]<-%s()[%lu]<-%s()[%lu]:",
                           now, thread, where,
                           unw_bt[0].func, unw_bt[0].ip,
                           unw_bt[1].func, unw_bt[1].ip,
                           unw_bt[2].func, unw_bt[2].ip,
                           unw_bt[3].func, unw_bt[3].ip);
            break;
        case 3:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s()[%lu]<-%s()[%lu]<-%s()[%lu]:",
                           now, thread, where,
                           unw_bt[0].func, unw_bt[0].ip,
                           unw_bt[1].func, unw_bt[1].ip,
                           unw_bt[2].func, unw_bt[2].ip);
            break;
        case 2:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s()[%lu]<-%s()[%lu]:",
                           now, thread, where,
                           unw_bt[0].func, unw_bt[0].ip,
                           unw_bt[1].func, unw_bt[1].ip);
            break;
        case 1:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s()[%lu]:",
                           now, thread, where,
                           unw_bt[0].func, unw_bt[0].ip);
            break;
        case 0:
        default:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|:",
                           now, thread, where);
            break;
   }
#elif HAVE_BACKTRACE
    char **stack_strings;
    void *stack_array[4];
    size_t stack_size;

    stack_size = backtrace(stack_array, ARRAY_SIZE(stack_array));
    stack_strings = backtrace_symbols(stack_array, stack_size);

    switch (stack_size) {
        case 4:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s<-%s<-%s<-%s|:",
                           now, thread, where, stack_strings[0],
                           stack_strings[1], stack_strings[2],
                           stack_strings[3]);
            break;
        case 3:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s<-%s<-%s:",
                           now, thread, where, stack_strings[0],
                           stack_strings[1], stack_strings[2]);
            break;
        case 2:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s<-%s:",
                           now, thread, where, stack_strings[0],
                           stack_strings[1]);
            break;
        case 1:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|%s:",
                           now, thread, where, stack_strings[0]);
            break;
        case 0:
        default:
            len = snprintf(line_buffer, sizeof line_buffer,
                           "%lld|%s|%s|:",
                           now, thread, where);
            break;
        }

        free(stack_strings);
#else
    len = snprintf(line_buffer, sizeof line_buffer, "%lld|%s|%s||:",
                   now, thread, where);
#endif

    va_start(args, message);

    if (len < sizeof line_buffer) {
        vsnprintf(line_buffer + len, sizeof line_buffer - len, message, args);
    }

    va_end(args);

    len = strlen(line_buffer);
    if (len >= (sizeof line_buffer)) {
        len = sizeof line_buffer;
        line_buffer[len - 1] = '\n';
    } else {
        line_buffer[len] = '\n';
        len++;
    }

    ec_dbg_add_buffer(line_buffer, len);
}

#define EC_DBG(...) \
    ec_dbg_at(OVS_SOURCE_LOCATOR, __VA_ARGS__);

#define EC_DBG_SETUP_BUFFER()                                        \
    struct ec_debug_buffer EC_DEBUG_BUFFER __attribute__((used)) = { \
        .size = EC_DEBUG_BUFFER_SIZE,                                \
        .start = 0,                                                  \
        .write = 0,                                                  \
        .mutex = OVS_MUTEX_INITIALIZER,                              \
    }

#endif /* EC_DEBUG_H */
