// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>
 *
 * fwx_offload_acct.c - MT7986(MTK PPE) 硬件加速流量统计补全
 *
 * 背景：
 *   用户流量原本由 kmod-fwx 在 netfilter 钩子处按报文计数，再通过 netlink
 *   上报给 fwxd。一旦连接被卸载到 MT7986 的 PPE（硬件加速）或 nf_flowtable
 *   （软件快速转发），报文就不再经过 netfilter 钩子，统计数据随之停滞。
 *
 * 做法：
 *   PPE 驱动通过 debugfs 导出每一条硬件转发表项的报文/字节计数
 *   (/sys/kernel/debug/ppeN/entries)，其中包含原始五元组。本模块周期性
 *   读取该表，按流做增量计算，再把增量并入 fwxd 原有的一套统计通路
 *   （今日汇总 / 分时统计 / 全局流量 / 本次会话），因此用户列表、详情页、
 *   流量统计、首页看板等所有位置无需改动即可获得加速流量。
 *
 *   注意：PPE 的 MIB 只提供每条流的总字节数（不区分上下行），所以上下行
 *   按该客户端最近在软件路径上的上下行比例来拆分（无样本时默认 20% 上行）。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <json-c/json.h>

#include "fwx.h"
#include "fwx_user.h"
#include "fwx_user_summary.h"
#include "fwx_offload_acct.h"

#define PPE_DEBUGFS_ROOT    "/sys/kernel/debug"
#define PPE_POLL_SECS       2
#define PPE_FLOW_SLOTS      8192
#define PPE_FLOW_MAX_AGE    3
#define PPE_KEY_LEN         96
#define PPE_LINE_LEN        2048
#define PPE_MAX_SOURCES     8

/* 上下行拆分的默认上行占比（缺少软件路径样本时使用） */
#define PPE_DEFAULT_UP_RATIO 0.2f
/* 累计超过该字节数才有足够的样本计算上下行比例 */
#define PPE_RATIO_MIN_BYTES (64ULL * 1024ULL)

extern traffic_stat_t g_global_hourly_traffic[HOURS_PER_DAY];
extern u_int32_t g_global_traffic_date;

typedef struct ppe_flow {
    char key[PPE_KEY_LEN];
    unsigned long long bytes;
    unsigned long long packets;
    int age;
    int used;
} ppe_flow_t;

static ppe_flow_t *g_flows;
static char g_sources[PPE_MAX_SOURCES][160];
static int g_source_cnt;
static time_t g_last_poll;
static int g_inited;
static unsigned long long g_hw_bytes_total;
static unsigned long long g_hw_bytes_last_log;

static u_int32_t ppe_hash(const char *s)
{
    u_int32_t h = 2166136261u;

    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }

    return h;
}

static ppe_flow_t *ppe_flow_slot(const char *key, int create)
{
    u_int32_t start;
    int i;

    if (!g_flows)
        return NULL;

    start = ppe_hash(key) % PPE_FLOW_SLOTS;

    for (i = 0; i < PPE_FLOW_SLOTS; i++) {
        ppe_flow_t *f = &g_flows[(start + i) % PPE_FLOW_SLOTS];

        if (!f->used) {
            if (!create)
                return NULL;

            f->used = 1;
            f->age = 0;
            f->bytes = 0;
            f->packets = 0;
            strncpy(f->key, key, PPE_KEY_LEN - 1);
            f->key[PPE_KEY_LEN - 1] = '\0';

            return f;
        }

        if (strcmp(f->key, key) == 0)
            return f;
    }

    return NULL;
}

/*
 * 把硬件加速的字节并入 fwxd 原有的统计通路。
 * 与 netlink 路径保持一致：每天 0 点后 2 分钟内不计入，避免跨天重复。
 */
static void ppe_account_apply(client_node_t *node, unsigned long long up,
                              unsigned long long down)
{
    time_t now;
    u_int32_t today_start;
    struct tm *tm_info;
    daily_hourly_stat_t *today_stat;
    int hour;

    if (!node || (up == 0 && down == 0))
        return;

    now = time(NULL);
    today_start = get_today_start_timestamp();

    if ((u_int32_t)now >= today_start && ((u_int32_t)now - today_start) < 120)
        return;

    update_client_daily_summary_bytes(node, now, up, down);

    tm_info = localtime(&now);
    hour = tm_info ? tm_info->tm_hour : -1;

    if (hour < 0 || hour >= HOURS_PER_DAY)
        return;

    today_stat = get_today_stat(node);
    if (today_stat) {
        today_stat->hourly_traffic[hour].up_bytes += up;
        today_stat->hourly_traffic[hour].down_bytes += down;
    }

    if (g_global_traffic_date != today_start) {
        memset(g_global_hourly_traffic, 0, sizeof(traffic_stat_t) * HOURS_PER_DAY);
        g_global_traffic_date = today_start;
    }

    g_global_hourly_traffic[hour].up_bytes += up;
    g_global_hourly_traffic[hour].down_bytes += down;

    update_online_session_flow(node, up, down);
}

static client_node_t *ppe_find_client_by_ip(const char *ip)
{
    client_node_t *node;

    if (!ip || !ip[0])
        return NULL;

    list_for_each_entry(node, &client_list, client) {
        if (node->ip[0] && strcmp(node->ip, ip) == 0)
            return node;
    }

    return NULL;
}

/* PPE MIB 只有单条流的总字节，按客户端软件路径的上下行比例拆分 */
static void ppe_account_bytes(client_node_t *node, unsigned long long bytes)
{
    unsigned long long sess_up, sess_down, up;
    double ratio = PPE_DEFAULT_UP_RATIO;

    if (!node || bytes == 0)
        return;

    sess_up = node->online_session.up_bytes;
    sess_down = node->online_session.down_bytes;

    if (sess_up + sess_down >= PPE_RATIO_MIN_BYTES)
        ratio = (double)sess_up / (double)(sess_up + sess_down);

    if (ratio < 0.02)
        ratio = 0.02;
    else if (ratio > 0.98)
        ratio = 0.98;

    up = (unsigned long long)((double)bytes * ratio);
    if (up > bytes)
        up = bytes;

    ppe_account_apply(node, up, bytes - up);
}

static char *ppe_next_space(char *p)
{
    while (*p && *p != ' ')
        p++;

    return p;
}

/*
 * 解析一行 FPGA 转发表项，形如：
 *   0001e bind ipv4  ppe=0 orig=192.168.1.100:51234->1.1.1.1:443 new=...
 *                   eth=..->.. etype=0800 vlan=0,0 ib1=.. ib2=.. packets=N bytes=M
 */
static int ppe_parse_line(char *line)
{
    char *p_bytes, *p_packets, *p_orig, *p_new, *p_ib1, *p_ib2, *sp;
    char orig[96], newt[96], ib1[16], ib2[16], key[PPE_KEY_LEN];
    char src[48], *arrow, *colon;
    unsigned long long bytes, packets;
    unsigned long idx;
    ppe_flow_t *flow;
    client_node_t *node;
    unsigned long long delta;
    char *endp;

    p_bytes = strstr(line, " bytes=");
    p_packets = strstr(line, " packets=");
    p_orig = strstr(line, " orig=");

    if (!p_bytes || !p_packets || !p_orig)
        return 0;

    bytes = strtoull(p_bytes + 7, NULL, 10);
    packets = strtoull(p_packets + 9, NULL, 10);

    /* 表项序号（行首十六进制） */
    idx = strtoul(line, &endp, 16);
    if (endp == line)
        return 0;

    /* 原始五元组 */
    p_orig += 6;
    sp = ppe_next_space(p_orig);
    if ((size_t)(sp - p_orig) >= sizeof(orig))
        return 0;
    memcpy(orig, p_orig, sp - p_orig);
    orig[sp - p_orig] = '\0';

    /* NAT 后的五元组 + ib1/ib2 用于识别表项复用 */
    newt[0] = '\0';
    ib1[0] = '\0';
    ib2[0] = '\0';

    p_new = strstr(line, " new=");
    if (p_new) {
        p_new += 5;
        sp = ppe_next_space(p_new);
        if ((size_t)(sp - p_new) < sizeof(newt)) {
            memcpy(newt, p_new, sp - p_new);
            newt[sp - p_new] = '\0';
        }
    }

    p_ib1 = strstr(line, " ib1=");
    if (p_ib1 && sscanf(p_ib1, " ib1=%15s ib2=%15s", ib1, ib2) < 1) {
        ib1[0] = '\0';
        ib2[0] = '\0';
    }

    snprintf(key, sizeof(key), "%lx|%s|%s|%s|%s", idx, ib1, ib2, orig, newt);

    /* 从原始五元组里取客户端地址（跳过 IPv6） */
    arrow = strstr(orig, "->");
    if (!arrow)
        return 0;

    snprintf(src, sizeof(src), "%.*s", (int)(arrow - orig), orig);

    colon = strchr(src, ':');
    if (colon) {
        /* 只保留 IPv4，出现第二个冒号说明是 IPv6 语义 */
        if (strchr(colon + 1, ':'))
            return 0;
        *colon = '\0';
    }

    if (!src[0])
        return 0;

    node = ppe_find_client_by_ip(src);
    if (!node)
        return 0;

    flow = ppe_flow_slot(key, 1);
    if (!flow)
        return 0;

    flow->age = 0;

    if (bytes < flow->bytes || packets < flow->packets) {
        /* 表项被新连接复用，按新流重新计数 */
        delta = bytes;
    } else {
        delta = bytes - flow->bytes;
    }

    flow->bytes = bytes;
    flow->packets = packets;

    if (delta > 0) {
        g_hw_bytes_total += delta;
        ppe_account_bytes(node, delta);
    }

    return 1;
}

static void ppe_age_flows(void)
{
    int i;

    if (!g_flows)
        return;

    for (i = 0; i < PPE_FLOW_SLOTS; i++) {
        if (!g_flows[i].used)
            continue;

        if (++g_flows[i].age > PPE_FLOW_MAX_AGE) {
            g_flows[i].used = 0;
            g_flows[i].key[0] = '\0';
        }
    }
}

static void ppe_add_source(const char *path)
{
    int i;

    if (g_source_cnt >= PPE_MAX_SOURCES)
        return;

    for (i = 0; i < g_source_cnt; i++) {
        if (strcmp(g_sources[i], path) == 0)
            return;
    }

    snprintf(g_sources[g_source_cnt], sizeof(g_sources[0]), "%s", path);
    g_source_cnt++;
}

static void ppe_discover_sources(void)
{
    char path[160];
    int i;

    g_source_cnt = 0;

    for (i = 0; i < 4; i++) {
        snprintf(path, sizeof(path), PPE_DEBUGFS_ROOT "/ppe%d/entries", i);
        if (access(path, R_OK) == 0)
            ppe_add_source(path);
    }

    /* 老内核路径 */
    if (g_source_cnt == 0) {
        snprintf(path, sizeof(path), PPE_DEBUGFS_ROOT "/mtk_ppe/entries");
        if (access(path, R_OK) == 0)
            ppe_add_source(path);
    }
}

static void ppe_mount_debugfs(void)
{
    /* 已挂载时 debugfs 根下会有 tracing 或 ppe 目录 */
    if (access(PPE_DEBUGFS_ROOT "/tracing", F_OK) == 0 ||
        access(PPE_DEBUGFS_ROOT "/ppe0", F_OK) == 0)
        return;

    if (access(PPE_DEBUGFS_ROOT, F_OK) != 0) {
        if (mkdir(PPE_DEBUGFS_ROOT, 0755) != 0 && errno != EEXIST) {
            LOG_ERROR("hw accel acct: create %s failed: %s\n",
                      PPE_DEBUGFS_ROOT, strerror(errno));
            return;
        }
    }

    if (mount("debugfs", PPE_DEBUGFS_ROOT, "debugfs", 0, NULL) == 0)
        LOG_INFO("hw accel acct: mounted debugfs for PPE statistics\n");
    else if (errno != EBUSY)
        LOG_DEBUG("hw accel acct: mount debugfs: %s\n", strerror(errno));
}

void fwx_offload_acct_init(void)
{
    if (g_inited)
        return;

    g_inited = 1;
    g_last_poll = 0;
    g_hw_bytes_total = 0;
    g_hw_bytes_last_log = 0;

    g_flows = calloc(PPE_FLOW_SLOTS, sizeof(ppe_flow_t));
    if (!g_flows) {
        LOG_ERROR("hw accel acct: no memory for flow table\n");
        return;
    }

    /* 让 /proc/net/nf_conntrack 也带上字节数，便于软件快速转发路径统计 */
    {
        FILE *fp = fopen("/proc/sys/net/netfilter/nf_conntrack_acct", "w");
        if (fp) {
            fputs("1\n", fp);
            fclose(fp);
        }
    }

    ppe_mount_debugfs();
    ppe_discover_sources();

    if (g_source_cnt > 0)
        LOG_INFO("hw accel acct: %d PPE table(s) found, hw offload accounting enabled\n",
                 g_source_cnt);
    else
        LOG_DEBUG("hw accel acct: no PPE table found, hw offload accounting idle\n");
}

void fwx_offload_acct_poll(void)
{
    time_t now;
    int i, seen = 0;

    if (!g_inited)
        fwx_offload_acct_init();

    if (!g_flows)
        return;

    now = time(NULL);
    if (g_last_poll != 0 && (now - g_last_poll) < PPE_POLL_SECS)
        return;
    g_last_poll = now;

    if (g_source_cnt == 0) {
        /* 硬件加速可能在运行期才被打开，定期重试探测 */
        ppe_mount_debugfs();
        ppe_discover_sources();
        if (g_source_cnt == 0)
            return;
    }

    ppe_age_flows();

    for (i = 0; i < g_source_cnt; i++) {
        FILE *fp = fopen(g_sources[i], "r");
        char line[PPE_LINE_LEN];

        if (!fp) {
            if (errno == ENOENT)
                g_source_cnt = 0;
            continue;
        }

        while (fgets(line, sizeof(line), fp)) {
            if (!strstr(line, "bytes="))
                continue;

            seen += ppe_parse_line(line);
        }

        fclose(fp);
    }

    if (g_hw_bytes_total - g_hw_bytes_last_log >= (10ULL * 1024ULL * 1024ULL)) {
        g_hw_bytes_last_log = g_hw_bytes_total;
        LOG_DEBUG("hw accel acct: %llu MB offloaded traffic accounted (%d active flows)\n",
                  g_hw_bytes_total / (1024ULL * 1024ULL), seen);
    }
}
