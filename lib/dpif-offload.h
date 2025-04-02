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

 #ifndef DPIF_OFFLOAD_H
 #define DPIF_OFFLOAD_H

 #include "dpif.h"

/* Forward declarations of private structures. */
struct dpif_offload_class;
struct dpif_offload;


/* Global functions. */
void dpif_offload_set_global_cfg(const struct smap *other_cfg);
bool dpif_offload_is_offload_enabled(void);
bool dpif_offload_is_offload_rebalance_policy_enabled(void);


/* Per dpif specific functions. */
void dpif_offload_init(struct dpif_offload *,
                       const struct dpif_offload_class *, struct dpif *);
int dpif_offload_attach_providers(struct dpif *);
void dpif_offload_detach_providers(struct dpif *);
const char *dpif_offload_name(const struct dpif_offload *);
const char *dpif_offload_class_type(const struct dpif_offload *);

#endif /* DPIF_OFFLOAD_H */
