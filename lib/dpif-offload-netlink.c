/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <linux/psample.h>
#include <sys/poll.h>

#include "dpif-offload-provider.h"
#include "id-pool.h"
#include "netdev-linux.h"
#include "netdev-offload.h"
#include "netlink-protocol.h"
#include "netlink-socket.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "tc.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_netlink);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static struct nl_sock *psample_sock;
static int psample_family;

/* Receive psample netlink message and save the attributes. */
struct offload_psample {
    struct nlattr *packet;      /* Packet data. */
    int dp_group_id;            /* Mapping id for sFlow offload. */
    int iifindex;               /* Input ifindex. */
};

static int meter_tc_init_policer(void);
static int meter_tc_destroy_policer(void);

/* In order to keep compatibility with kernels without psample module,
 * return success even if psample is not initialized successfully. */
static void
psample_init(void)
{
    unsigned int psample_mcgroup;
    int err;

    if (!netdev_is_flow_api_enabled()) {
        VLOG_DBG("Flow API is not enabled.");
        return;
    }

    if (psample_sock) {
        VLOG_DBG("Psample socket is already initialized.");
        return;
    }

    err = nl_lookup_genl_family(PSAMPLE_GENL_NAME,
                                &psample_family);
    if (err) {
        VLOG_WARN("Generic Netlink family '%s' does not exist: %s\n"
                  "Please make sure the kernel module psample is loaded.",
                  PSAMPLE_GENL_NAME, ovs_strerror(err));
        return;
    }

    err = nl_lookup_genl_mcgroup(PSAMPLE_GENL_NAME,
                                 PSAMPLE_NL_MCGRP_SAMPLE_NAME,
                                 &psample_mcgroup);
    if (err) {
        VLOG_WARN("Failed to join Netlink multicast group '%s': %s",
                  PSAMPLE_NL_MCGRP_SAMPLE_NAME, ovs_strerror(err));
        return;
    }

    err = nl_sock_create(NETLINK_GENERIC, &psample_sock);
    if (err) {
        VLOG_WARN("Failed to create psample socket: %s", ovs_strerror(err));
        return;
    }

    err = nl_sock_join_mcgroup(psample_sock, psample_mcgroup);
    if (err) {
        VLOG_WARN("Failed to join psample mcgroup: %s", ovs_strerror(err));
        nl_sock_destroy(psample_sock);
        psample_sock = NULL;
        return;
    }
}

static int
dpif_offload_netlink_init(void)
{
    psample_init();

    meter_tc_init_policer();

    return 0;
}

static void
psample_destroy(void)
{
    if (!psample_sock) {
        return;
    }

    nl_sock_destroy(psample_sock);
    psample_sock = NULL;
}

static void
dpif_offload_netlink_destroy(void)
{
    psample_destroy();

    meter_tc_destroy_policer();
}

static void
dpif_offload_netlink_sflow_recv_wait(void)
{
    if (psample_sock) {
        nl_sock_wait(psample_sock, POLLIN);
    }
}

static int
psample_from_ofpbuf(struct offload_psample *psample,
                    const struct ofpbuf *buf)
{
    static const struct nl_policy ovs_psample_policy[] = {
        [PSAMPLE_ATTR_IIFINDEX] = { .type = NL_A_U16 },
        [PSAMPLE_ATTR_SAMPLE_GROUP] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_GROUP_SEQ] = { .type = NL_A_U32 },
        [PSAMPLE_ATTR_DATA] = { .type = NL_A_UNSPEC },
    };
    struct nlattr *a[ARRAY_SIZE(ovs_psample_policy)];
    struct genlmsghdr *genl;
    struct nlmsghdr *nlmsg;
    struct ofpbuf b;

    b = ofpbuf_const_initializer(buf->data, buf->size);
    nlmsg = ofpbuf_try_pull(&b, sizeof *nlmsg);
    genl = ofpbuf_try_pull(&b, sizeof *genl);
    if (!nlmsg || !genl || nlmsg->nlmsg_type != psample_family
        || !nl_policy_parse(&b, 0, ovs_psample_policy, a,
                            ARRAY_SIZE(ovs_psample_policy))) {
        return EINVAL;
    }

    psample->iifindex = nl_attr_get_u16(a[PSAMPLE_ATTR_IIFINDEX]);
    psample->dp_group_id = nl_attr_get_u32(a[PSAMPLE_ATTR_SAMPLE_GROUP]);
    psample->packet = a[PSAMPLE_ATTR_DATA];

    return 0;
}

static int
psample_parse_packet(struct offload_psample *psample,
                     struct dpif_offload_sflow *sflow)
{
    dp_packet_use_stub(&sflow->packet,
                       CONST_CAST(struct nlattr *,
                                  nl_attr_get(psample->packet)) - 1,
                       nl_attr_get_size(psample->packet) +
                       sizeof(struct nlattr));
    dp_packet_set_data(&sflow->packet,
                       (char *) dp_packet_data(&sflow->packet) +
                       sizeof(struct nlattr));
    dp_packet_set_size(&sflow->packet, nl_attr_get_size(psample->packet));

    sflow->attr = dpif_offload_sflow_attr_find(psample->dp_group_id);
    if (!sflow->attr) {
        return ENOENT;
    }
    sflow->iifindex = psample->iifindex;

    return 0;
}

static int
dpif_offload_netlink_sflow_recv(struct dpif_offload_sflow *sflow)
{
    if (!psample_sock) {
        return ENOENT;
    }

    for (;;) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        struct offload_psample psample;
        uint64_t buf_stub[4096 / 8];
        struct ofpbuf buf;
        int error;

        ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
        error = nl_sock_recv(psample_sock, &buf, NULL, false);

        if (!error) {
            error = psample_from_ofpbuf(&psample, &buf);
            if (!error) {
                    ofpbuf_uninit(&buf);
                    error = psample_parse_packet(&psample, sflow);
                    return error;
            }
        } else if (error != EAGAIN) {
            VLOG_WARN_RL(&rl, "Error reading or parsing netlink (%s).",
                         ovs_strerror(error));
            nl_sock_drain(psample_sock);
            error = ENOBUFS;
        }

        ofpbuf_uninit(&buf);
        if (error) {
            return error;
        }
    }
}

#define METER_POLICE_IDS_BASE 0x10000000
#define METER_POLICE_IDS_MAX  0x1FFFFFFF
/* Protects below meter ids pool and hashmaps. */
static struct ovs_mutex meter_mutex = OVS_MUTEX_INITIALIZER;
static struct id_pool *meter_police_ids;
static struct hmap meter_id_to_police_idx OVS_GUARDED_BY(meter_mutex)
    = HMAP_INITIALIZER(&meter_id_to_police_idx);

struct meter_id_to_police_idx_data {
    struct hmap_node meter_id_node;
    uint32_t meter_id;
    uint32_t police_idx;
};

static struct meter_id_to_police_idx_data *
meter_id_find_locked(uint32_t meter_id)
    OVS_REQUIRES(meter_mutex)
{
    struct meter_id_to_police_idx_data *data;
    size_t hash = hash_int(meter_id, 0);

    HMAP_FOR_EACH_WITH_HASH (data, meter_id_node, hash,
                             &meter_id_to_police_idx) {
        if (data->meter_id == meter_id) {
            return data;
        }
    }

    return NULL;
}

static int
meter_id_lookup(uint32_t meter_id, uint32_t *police_idx)
{
    struct meter_id_to_police_idx_data *data;
    int ret = 0;

    ovs_mutex_lock(&meter_mutex);
    data = meter_id_find_locked(meter_id);
    if (data) {
        *police_idx = data->police_idx;
    } else {
        ret = ENOENT;
    }
    ovs_mutex_unlock(&meter_mutex);

    return ret;
}

static void
meter_id_insert(uint32_t meter_id, uint32_t police_idx)
{
    struct meter_id_to_police_idx_data *data;

    ovs_mutex_lock(&meter_mutex);
    data = meter_id_find_locked(meter_id);
    if (!data) {
        data = xzalloc(sizeof *data);
        data->meter_id = meter_id;
        data->police_idx = police_idx;
        hmap_insert(&meter_id_to_police_idx, &data->meter_id_node,
                    hash_int(meter_id, 0));
    } else {
        VLOG_WARN_RL(&error_rl,
                     "try to insert meter %u (%u) with different police (%u)",
                     meter_id, data->police_idx, police_idx);
    }
    ovs_mutex_unlock(&meter_mutex);
}

static void
meter_id_remove(uint32_t meter_id)
{
    struct meter_id_to_police_idx_data *data;

    ovs_mutex_lock(&meter_mutex);
    data = meter_id_find_locked(meter_id);
    if (data) {
        hmap_remove(&meter_id_to_police_idx, &data->meter_id_node);
        free(data);
    }
    ovs_mutex_unlock(&meter_mutex);
}

static bool
meter_alloc_police_index(uint32_t *police_index)
{
    bool ret;

    ovs_mutex_lock(&meter_mutex);
    ret = id_pool_alloc_id(meter_police_ids, police_index);
    ovs_mutex_unlock(&meter_mutex);

    return ret;
}

static void
meter_free_police_index(uint32_t police_index)
{
    ovs_mutex_lock(&meter_mutex);
    id_pool_free_id(meter_police_ids, police_index);
    ovs_mutex_unlock(&meter_mutex);
}

static int
meter_tc_set_policer(ofproto_meter_id meter_id,
                     struct ofputil_meter_config *config)
{
    uint32_t police_index;
    uint32_t rate, burst;
    bool add_policer;
    int err;

    ovs_assert(config->bands != NULL);

    rate = config->bands[0].rate;
    if (config->flags & OFPMF13_BURST) {
        burst = config->bands[0].burst_size;
    } else {
        burst = config->bands[0].rate;
    }

    add_policer = (meter_id_lookup(meter_id.uint32, &police_index) == ENOENT);
    if (add_policer) {
        if (!meter_alloc_police_index(&police_index)) {
            VLOG_WARN_RL(&error_rl, "no free police index for meter id %u",
                         meter_id.uint32);
            return ENOENT;
        }
    }

    err = tc_add_policer_action(police_index,
                                (config->flags & OFPMF13_KBPS) ? rate : 0,
                                (config->flags & OFPMF13_KBPS) ? burst : 0,
                                (config->flags & OFPMF13_PKTPS) ? rate : 0,
                                (config->flags & OFPMF13_PKTPS) ? burst : 0,
                                !add_policer);
    if (err) {
        VLOG_WARN_RL(&error_rl,
                     "failed to %s police %u for meter id %u: %s",
                     add_policer ? "add" : "modify",
                     police_index, meter_id.uint32, ovs_strerror(err));
        goto err_add_policer;
    }

    if (add_policer) {
        meter_id_insert(meter_id.uint32, police_index);
    }

    return 0;

err_add_policer:
    if (add_policer) {
        meter_free_police_index(police_index);
    }
    return err;
}

static int
meter_tc_get_policer(ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *stats,
                     uint16_t max_bands OVS_UNUSED)
{
    uint32_t police_index;
    int err = 0;

    if (!meter_id_lookup(meter_id.uint32, &police_index)) {
        err = tc_get_policer_action(police_index, stats);
        if (err) {
            VLOG_WARN_RL(&error_rl,
                         "failed to get police %u stats for meter %u: %s",
                         police_index, meter_id.uint32, ovs_strerror(err));
        }
    }

    return err;
}

static int
meter_tc_del_policer(ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *stats,
                     uint16_t max_bands OVS_UNUSED)
{
    uint32_t police_index;
    int err = 0;

    if (!meter_id_lookup(meter_id.uint32, &police_index)) {
        err = tc_del_policer_action(police_index, stats);
        if (err) {
            VLOG_WARN_RL(&error_rl,
                         "failed to del police %u for meter %u: %s",
                         police_index, meter_id.uint32, ovs_strerror(err));
        } else {
            meter_free_police_index(police_index);
        }
        meter_id_remove(meter_id.uint32);
    }

    return err;
}

struct policer_node {
    struct hmap_node node;
    uint32_t police_idx;
};

static int
tc_get_policer_action_ids(struct hmap *map)
{
    uint32_t police_idx[TCA_ACT_MAX_PRIO] = {};
    struct policer_node *policer_node;
    struct netdev_flow_dump *dump;
    struct ofpbuf rbuffer, reply;
    size_t hash;
    int i, err;

    dump = xzalloc(sizeof *dump);
    dump->nl_dump = xzalloc(sizeof *dump->nl_dump);

    ofpbuf_init(&rbuffer, NL_DUMP_BUFSIZE);
    tc_dump_tc_action_start("police", dump->nl_dump);

    while (nl_dump_next(dump->nl_dump, &reply, &rbuffer)) {
        if (parse_netlink_to_tc_policer(&reply, police_idx)) {
            continue;
        }

        for (i = 0; i < TCA_ACT_MAX_PRIO; i++) {
            if (!police_idx[i]) {
                break;
            }
            policer_node = xzalloc(sizeof *policer_node);
            policer_node->police_idx = police_idx[i];
            hash = hash_int(police_idx[i], 0);
            hmap_insert(map, &policer_node->node, hash);
        }
        memset(police_idx, 0, TCA_ACT_MAX_PRIO * sizeof(uint32_t));
    }

    err = nl_dump_done(dump->nl_dump);
    ofpbuf_uninit(&rbuffer);
    free(dump->nl_dump);
    free(dump);

    return err;
}

static void
tc_cleanup_policer_action(struct id_pool *police_ids,
                          uint32_t id_min, uint32_t id_max)
{
    struct policer_node *policer_node;
    uint32_t police_idx;
    struct hmap map;
    int err;

    hmap_init(&map);
    tc_get_policer_action_ids(&map);

    HMAP_FOR_EACH_POP (policer_node, node, &map) {
        police_idx = policer_node->police_idx;
        if (police_idx >= id_min && police_idx <= id_max) {
            err = tc_del_policer_action(police_idx, NULL);
            if (err) {
                /* don't use this police any more */
                id_pool_add(police_ids, police_idx);
            }
        }
        free(policer_node);
    }

    hmap_destroy(&map);
}

static int
meter_tc_init_policer(void)
{
    meter_police_ids = id_pool_create(METER_POLICE_IDS_BASE,
                METER_POLICE_IDS_MAX - METER_POLICE_IDS_BASE + 1);

    tc_cleanup_policer_action(meter_police_ids, METER_POLICE_IDS_BASE,
                              METER_POLICE_IDS_MAX);

    return 0;
}

static int
meter_tc_destroy_policer(void)
{
    id_pool_destroy(meter_police_ids);

    return 0;
}

const struct dpif_offload_class dpif_offload_netlink_class = {
    .type = "system",
    .init = dpif_offload_netlink_init,
    .destroy = dpif_offload_netlink_destroy,
    .sflow_recv_wait = dpif_offload_netlink_sflow_recv_wait,
    .sflow_recv = dpif_offload_netlink_sflow_recv,
    .meter_set = meter_tc_set_policer,
    .meter_get = meter_tc_get_policer,
    .meter_del = meter_tc_del_policer,
};

bool
dpif_offload_netlink_psample_supported(void)
{
    return psample_sock != NULL;
}
