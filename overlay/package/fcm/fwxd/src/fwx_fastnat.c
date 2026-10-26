// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <uci.h>
#include "fwx.h"
#include "fwx_uci.h"
#include "fwx_fastnat.h"

#define FASTNAT_ENABLED_PATH "/sys/sfe_cm/enabled"
#define FASTNAT_DPI_PATH "/sys/sfe_cm/dpi_compat"

struct fastnat_config {
    int enabled;
    int dpi_compat;
};

struct fastnat_totals {
    uint64_t packets;
    uint64_t connections;
    uint64_t accelerated;
    uint64_t accelerated_bytes;
    int available;
};

static struct json_object *fastnat_error(const char *message)
{
    struct json_object *resp = fwx_gen_api_response_data(API_CODE_ERROR, NULL);

    if (resp)
        json_object_object_add(resp, "message", json_object_new_string(message));
    return resp;
}

static int fastnat_read_switch(const char *path, int *value)
{
    FILE *fp = fopen(path, "r");
    int result;

    if (!fp)
        return -1;
    result = fscanf(fp, "%d", value);
    fclose(fp);
    return result == 1 && (*value == 0 || *value == 1) ? 0 : -1;
}

static int fastnat_write_switch(const char *path, int value)
{
    FILE *fp = fopen(path, "w");
    int written, closed, current;

    if (!fp)
        return -1;
    written = fprintf(fp, "%d\n", value);
    closed = fclose(fp);
    if (written < 0 || closed != 0)
        return -1;
    return fastnat_read_switch(path, &current) == 0 && current == value ? 0 : -1;
}

static int fastnat_read_config(struct fastnat_config *config)
{
    struct uci_context *ctx = uci_alloc_context();
    char value[8];

    config->enabled = 0;
    config->dpi_compat = 1;
    if (!ctx)
        return -1;
    if (fwx_uci_get_value(ctx, "fastnat.global.enabled", value, sizeof(value)) == 0)
        config->enabled = strcmp(value, "0") != 0;
    if (fwx_uci_get_value(ctx, "fastnat.global.dpi_compat", value, sizeof(value)) == 0)
        config->dpi_compat = strcmp(value, "0") != 0;
    uci_free_context(ctx);
    return 0;
}

static int fastnat_set_uci(struct uci_context *ctx, const char *assignment)
{
    struct uci_ptr ptr;
    char path[96];

    snprintf(path, sizeof(path), "%s", assignment);
    if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK)
        return -1;
    return uci_set(ctx, &ptr) == UCI_OK ? 0 : -1;
}

static int fastnat_save_config(const struct fastnat_config *config)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    char assignment[64];
    int result = -1;

    if (!ctx)
        return -1;
    if (uci_load(ctx, "fastnat", &pkg) != UCI_OK ||
        fastnat_set_uci(ctx, "fastnat.global=fastnat") != 0)
        goto out;
    snprintf(assignment, sizeof(assignment), "fastnat.global.enabled=%d", config->enabled);
    if (fastnat_set_uci(ctx, assignment) != 0)
        goto out;
    snprintf(assignment, sizeof(assignment), "fastnat.global.dpi_compat=%d", config->dpi_compat);
    if (fastnat_set_uci(ctx, assignment) != 0)
        goto out;
    result = uci_commit(ctx, &pkg, false) == UCI_OK ? 0 : -1;
out:
    uci_free_context(ctx);
    return result;
}

static int fastnat_apply_config(const struct fastnat_config *config)
{
    if (!config->enabled && fastnat_write_switch(FASTNAT_ENABLED_PATH, 0) != 0)
        return -1;
    if (fastnat_write_switch(FASTNAT_DPI_PATH, config->dpi_compat) != 0)
        return -1;
    return fastnat_write_switch(FASTNAT_ENABLED_PATH, config->enabled);
}

static void fastnat_read_stats(const char *path, struct fastnat_totals *totals)
{
    FILE *fp = fopen(path, "r");
    char line[160], key[64];
    uint64_t value;

    if (!fp)
        return;
    totals->available = 1;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, " %63[^= ] = %" SCNu64, key, &value) != 2)
            continue;
        if (strcmp(key, "num_connections") == 0)
            totals->connections += value;
        else if (strcmp(key, "pkts_forwarded") == 0) {
            totals->accelerated += value;
            totals->packets += value;
        } else if (strcmp(key, "bytes_forwarded") == 0) {
            totals->accelerated_bytes += value;
        } else if (strcmp(key, "pkts_not_forwarded") == 0) {
            totals->packets += value;
        }
    }
    fclose(fp);
}

static void fastnat_add_counter(struct json_object *obj, const char *name, uint64_t value)
{
    char text[32];

    snprintf(text, sizeof(text), "%" PRIu64, value);
    json_object_object_add(obj, name, json_object_new_string(text));
}

struct json_object *fwx_api_get_fastnat_status(struct json_object *req_obj)
{
    struct fastnat_config config, runtime = { 0, 1 };
    struct fastnat_totals totals = { 0 };
    struct json_object *data, *counts;
    int loaded;

    if (fastnat_read_config(&config) != 0)
        return fastnat_error("Failed to load Fastnat configuration");
    loaded = fastnat_read_switch(FASTNAT_ENABLED_PATH, &runtime.enabled) == 0;
    loaded = fastnat_read_switch(FASTNAT_DPI_PATH, &runtime.dpi_compat) == 0 && loaded;
    fastnat_read_stats("/proc/sfe_ipv4/sfe_ipv4_stat", &totals);
    fastnat_read_stats("/proc/sfe_ipv6/sfe_ipv6_stat", &totals);
    data = json_object_new_object();
    counts = json_object_new_object();
    if (!data || !counts) {
        if (data) json_object_put(data);
        if (counts) json_object_put(counts);
        return fastnat_error("Failed to load status");
    }
    json_object_object_add(data, "loaded", json_object_new_boolean(loaded));
    json_object_object_add(data, "enabled", json_object_new_boolean(loaded && runtime.enabled));
    json_object_object_add(data, "dpi_compat", json_object_new_boolean(loaded && runtime.dpi_compat));
    json_object_object_add(data, "configured_enabled", json_object_new_boolean(config.enabled));
    json_object_object_add(data, "configured_dpi_compat", json_object_new_boolean(config.dpi_compat));
    json_object_object_add(data, "stats_available", json_object_new_boolean(totals.available));
    fastnat_add_counter(counts, "total_packets", totals.packets);
    fastnat_add_counter(counts, "total_connections", totals.connections);
    fastnat_add_counter(counts, "accelerated_packets", totals.accelerated);
    fastnat_add_counter(counts, "accelerated_bytes", totals.accelerated_bytes);
    json_object_object_add(data, "totals", counts);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *fwx_api_get_fastnat_config(struct json_object *req_obj)
{
    struct fastnat_config config;
    struct json_object *data;

    if (fastnat_read_config(&config) != 0)
        return fastnat_error("Failed to load Fastnat configuration");
    data = json_object_new_object();
    if (!data)
        return fastnat_error("Failed to load Fastnat configuration");
    json_object_object_add(data, "enabled", json_object_new_boolean(config.enabled));
    json_object_object_add(data, "dpi_compat", json_object_new_boolean(config.dpi_compat));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int fastnat_parse_switch(struct json_object *data, const char *name, int *value)
{
    struct json_object *item;
    const char *text;

    if (!json_object_object_get_ex(data, name, &item))
        return 0;
    if (!item)
        return -1;
    if (json_object_is_type(item, json_type_boolean)) {
        *value = json_object_get_boolean(item);
        return 1;
    }
    if (!json_object_is_type(item, json_type_int) &&
        !json_object_is_type(item, json_type_string))
        return -1;
    text = json_object_get_string(item);
    if (strcmp(text, "0") != 0 && strcmp(text, "1") != 0)
        return -1;
    *value = text[0] == '1';
    return 1;
}

struct json_object *fwx_api_set_fastnat_config(struct json_object *req_obj)
{
    struct fastnat_config config, previous;
    int enabled, dpi_compat;

    if (!req_obj || !json_object_is_type(req_obj, json_type_object))
        return fastnat_error("Invalid switch value");
    if (fastnat_read_config(&config) != 0)
        return fastnat_error("Failed to load Fastnat configuration");
    enabled = fastnat_parse_switch(req_obj, "enabled", &config.enabled);
    dpi_compat = fastnat_parse_switch(req_obj, "dpi_compat", &config.dpi_compat);
    if (enabled < 0 || dpi_compat < 0 || (!enabled && !dpi_compat))
        return fastnat_error("Invalid switch value");
    if (fastnat_read_switch(FASTNAT_ENABLED_PATH, &previous.enabled) != 0 ||
        fastnat_read_switch(FASTNAT_DPI_PATH, &previous.dpi_compat) != 0)
        return fastnat_error("Fastnat controls are unavailable");
    if (fastnat_apply_config(&config) != 0) {
        if (fastnat_apply_config(&previous) != 0)
            return fastnat_error("Failed to apply settings and restore engine state");
        return fastnat_error("Failed to apply acceleration setting");
    }
    if (fastnat_save_config(&config) != 0) {
        if (fastnat_apply_config(&previous) != 0)
            return fastnat_error("Failed to save setting and restore engine state");
        return fastnat_error("Failed to save acceleration setting");
    }
    return fwx_api_get_fastnat_status(NULL);
}
