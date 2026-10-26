// SPDX-License-Identifier: GPL-2.0-or-later
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uci.h>
#include <unistd.h>

#include "fwx.h"
#include "fwx_ddns.h"

#define DDNS_CONFIG "ddns"
#define DDNS_DEFAULT_RUNDIR "/var/run/ddns"
#define DDNS_PROVIDER_LIMIT 512

typedef struct {
    int require_username;
    int require_password;
    int show_username;
    int show_password;
    int require_param_enc;
    int require_param_opt;
    int use_https;
} ddns_provider_info_t;

static struct json_object *ddns_error(const char *message)
{
    struct json_object *data = json_object_new_object();

    if (data && message)
        json_object_object_add(data, "message", json_object_new_string(message));
    return fwx_gen_api_response_data(API_CODE_ERROR, data);
}

static const char *uci_option_string(struct uci_context *ctx,
                                     struct uci_section *section,
                                     const char *name)
{
    struct uci_option *option;

    option = uci_lookup_option(ctx, section, name);
    if (!option || option->type != UCI_TYPE_STRING)
        return "";
    return option->v.string ? option->v.string : "";
}

static int uci_option_int(struct uci_context *ctx, struct uci_section *section,
                          const char *name, int fallback)
{
    const char *value = uci_option_string(ctx, section, name);

    return value[0] ? atoi(value) : fallback;
}

static int set_option(struct uci_context *ctx, struct uci_package *package,
                      struct uci_section *section, const char *name,
                      const char *value)
{
    struct uci_ptr ptr = {
        .p = package,
        .s = section,
        .section = section->e.name,
        .option = name,
        .value = value
    };

    return uci_set(ctx, &ptr);
}

static int delete_option(struct uci_context *ctx, struct uci_package *package,
                         struct uci_section *section, const char *name)
{
    struct uci_option *option = uci_lookup_option(ctx, section, name);
    struct uci_ptr ptr = { .p = package, .s = section, .o = option };

    if (!option)
        return UCI_OK;
    return uci_delete(ctx, &ptr);
}

static void trim_string(char *value)
{
    char *start = value;
    size_t len;

    while (*start && isspace((unsigned char)*start))
        start++;
    if (start != value)
        memmove(value, start, strlen(start) + 1);
    len = strlen(value);
    while (len > 0 && isspace((unsigned char)value[len - 1]))
        value[--len] = '\0';
}

static int has_control(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    while (*p) {
        if (*p < 0x20 || *p == 0x7f)
            return 1;
        p++;
    }
    return 0;
}

static int valid_section_id(const char *id)
{
    size_t i;

    if (!id || !id[0] || strlen(id) > 63)
        return 0;
    for (i = 0; id[i]; i++) {
        if (!isalnum((unsigned char)id[i]) && id[i] != '_' && id[i] != '-')
            return 0;
    }
    return 1;
}

static int valid_lookup_host(const char *host)
{
    size_t i, len;

    if (!host)
        return 0;
    len = strlen(host);
    if (len == 0 || len > 253)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)host[i];
        if (!isalnum(c) && c != '.' && c != '-' && c != '_' && c != ':')
            return 0;
    }
    return 1;
}

static int valid_domain(const char *domain)
{
    size_t i, len;

    if (!domain)
        return 0;
    len = strlen(domain);
    if (len == 0 || len > 255)
        return 0;
    for (i = 0; i < len; i++) {
        if (isspace((unsigned char)domain[i]) || iscntrl((unsigned char)domain[i]))
            return 0;
    }
    return 1;
}

static int provider_from_file(const char *path, const char *name, int use_ipv6,
                              ddns_provider_info_t *info)
{
    struct json_object *root = NULL;
    struct json_object *name_obj = NULL;
    struct json_object *family = NULL;
    struct json_object *url_obj = NULL;
    const char *url;
    int found = 0;

    root = json_object_from_file(path);
    if (!root || !json_object_is_type(root, json_type_object))
        goto done;
    if (!json_object_object_get_ex(root, "name", &name_obj) ||
        !json_object_is_type(name_obj, json_type_string) ||
        strcmp(json_object_get_string(name_obj), name) != 0)
        goto done;
    if (!json_object_object_get_ex(root, use_ipv6 ? "ipv6" : "ipv4", &family) ||
        !json_object_is_type(family, json_type_object))
        goto done;
    if (!json_object_object_get_ex(family, "url", &url_obj) ||
        !json_object_is_type(url_obj, json_type_string))
        goto done;
    url = json_object_get_string(url_obj);
    if (!url || !url[0])
        goto done;
    if (info) {
        memset(info, 0, sizeof(*info));
        int script_provider = strncasecmp(url, "http://", 7) != 0 &&
                              strncasecmp(url, "https://", 8) != 0;
        info->require_username = strstr(url, "[USERNAME]") != NULL;
        info->require_password = strstr(url, "[PASSWORD]") != NULL;
        info->show_username = info->require_username || script_provider;
        info->show_password = info->require_password || script_provider;
        info->require_param_enc = strstr(url, "[PARAMENC]") != NULL;
        info->require_param_opt = strstr(url, "[PARAMOPT]") != NULL;
        info->use_https = strncasecmp(url, "https://", 8) == 0 || script_provider;
    }
    found = 1;
done:
    if (root)
        json_object_put(root);
    return found;
}

static int find_provider(const char *name, int use_ipv6, ddns_provider_info_t *info)
{
    static const char *dirs[] = {
        "/usr/share/ddns/custom",
        "/usr/share/ddns/default"
    };
    size_t d;

    for (d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
        DIR *dir = opendir(dirs[d]);
        struct dirent *entry;

        if (!dir)
            continue;
        while ((entry = readdir(dir)) != NULL) {
            char path[512];
            size_t len = strlen(entry->d_name);

            if (len < 6 || strcmp(entry->d_name + len - 5, ".json") != 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", dirs[d], entry->d_name);
            if (provider_from_file(path, name, use_ipv6, info)) {
                closedir(dir);
                return 1;
            }
        }
        closedir(dir);
    }
    return 0;
}

static int provider_exists_in_array(struct json_object *array, const char *name)
{
    size_t i;

    for (i = 0; i < json_object_array_length(array); i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        struct json_object *name_obj = NULL;

        if (json_object_object_get_ex(item, "name", &name_obj) &&
            strcmp(json_object_get_string(name_obj), name) == 0)
            return 1;
    }
    return 0;
}

static void append_providers_from_dir(struct json_object *array, const char *dir_path,
                                      int use_ipv6)
{
    DIR *dir = opendir(dir_path);
    struct dirent *entry;

    if (!dir)
        return;
    while ((entry = readdir(dir)) != NULL &&
           json_object_array_length(array) < DDNS_PROVIDER_LIMIT) {
        struct json_object *root = NULL;
        struct json_object *name_obj = NULL;
        const char *name;
        ddns_provider_info_t info;
        struct json_object *item;
        char path[512];
        size_t len = strlen(entry->d_name);

        if (len < 6 || strcmp(entry->d_name + len - 5, ".json") != 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        root = json_object_from_file(path);
        if (!root || !json_object_is_type(root, json_type_object)) {
            if (root)
                json_object_put(root);
            continue;
        }
        if (!json_object_object_get_ex(root, "name", &name_obj) ||
            !json_object_is_type(name_obj, json_type_string)) {
            json_object_put(root);
            continue;
        }
        name = json_object_get_string(name_obj);
        if (!name || !name[0] || provider_exists_in_array(array, name) ||
            !provider_from_file(path, name, use_ipv6, &info)) {
            json_object_put(root);
            continue;
        }
        item = json_object_new_object();
        json_object_object_add(item, "name", json_object_new_string(name));
        json_object_object_add(item, "require_username", json_object_new_int(info.require_username));
        json_object_object_add(item, "require_password", json_object_new_int(info.require_password));
        json_object_object_add(item, "show_username", json_object_new_int(info.show_username));
        json_object_object_add(item, "show_password", json_object_new_int(info.show_password));
        json_object_object_add(item, "require_param_enc", json_object_new_int(info.require_param_enc));
        json_object_object_add(item, "require_param_opt", json_object_new_int(info.require_param_opt));
        json_object_object_add(item, "use_https", json_object_new_int(info.use_https));
        json_object_array_add(array, item);
        json_object_put(root);
    }
    closedir(dir);
}

static int compare_provider_items(const void *a, const void *b)
{
    struct json_object *left = *(struct json_object **)a;
    struct json_object *right = *(struct json_object **)b;
    struct json_object *left_name = NULL;
    struct json_object *right_name = NULL;

    json_object_object_get_ex(left, "name", &left_name);
    json_object_object_get_ex(right, "name", &right_name);
    return strcasecmp(json_object_get_string(left_name), json_object_get_string(right_name));
}

static int read_first_line(const char *path, char *buffer, size_t length)
{
    FILE *fp = fopen(path, "r");

    if (!fp)
        return -1;
    if (!fgets(buffer, (int)length, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    trim_string(buffer);
    return 0;
}

static void get_runtime_dir(struct uci_context *ctx, struct uci_package *package,
                            char *buffer, size_t length)
{
    struct uci_section *global = uci_lookup_section(ctx, package, "global");
    const char *configured = global ? uci_option_string(ctx, global, "ddns_rundir") : "";

    if (configured[0] == '/' && !strstr(configured, ".."))
        snprintf(buffer, length, "%s", configured);
    else
        snprintf(buffer, length, "%s", DDNS_DEFAULT_RUNDIR);
}

static int section_running(const char *runtime_dir, const char *section)
{
    char path[512];
    char value[32] = {0};
    char proc_path[64];
    long pid;

    snprintf(path, sizeof(path), "%s/%s.pid", runtime_dir, section);
    if (read_first_line(path, value, sizeof(value)) != 0)
        return 0;
    pid = strtol(value, NULL, 10);
    if (pid <= 1)
        return 0;
    snprintf(proc_path, sizeof(proc_path), "/proc/%ld", pid);
    return access(proc_path, F_OK) == 0;
}

static long long section_last_update(const char *runtime_dir, const char *section)
{
    char path[512];
    char value[64] = {0};
    char uptime_value[64] = {0};
    long long update_uptime;
    double uptime;

    snprintf(path, sizeof(path), "%s/%s.update", runtime_dir, section);
    if (read_first_line(path, value, sizeof(value)) != 0 ||
        read_first_line("/proc/uptime", uptime_value, sizeof(uptime_value)) != 0)
        return 0;
    update_uptime = strtoll(value, NULL, 10);
    uptime = strtod(uptime_value, NULL);
    if (update_uptime <= 0 || uptime <= 0 || (double)update_uptime > uptime)
        return 0;
    return (long long)time(NULL) - (long long)uptime + update_uptime;
}

static int run_ddns_action(const char *action, const char *section)
{
    pid_t pid;
    int status;

    if (!action || !section || !valid_section_id(section))
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO)
                close(fd);
        }
        execl("/etc/init.d/ddns", "ddns", action, section, (char *)NULL);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static struct json_object *service_to_json(struct uci_context *ctx,
                                           struct uci_section *section,
                                           const char *runtime_dir)
{
    struct json_object *item = json_object_new_object();
    char path[512];
    char current_ip[128] = {0};
    const char *name = uci_option_string(ctx, section, "profile_name");
    const char *password = uci_option_string(ctx, section, "password");

    snprintf(path, sizeof(path), "%s/%s.ip", runtime_dir, section->e.name);
    read_first_line(path, current_ip, sizeof(current_ip));
    json_object_object_add(item, "id", json_object_new_string(section->e.name));
    json_object_object_add(item, "name", json_object_new_string(name[0] ? name : section->e.name));
    json_object_object_add(item, "enabled", json_object_new_int(uci_option_int(ctx, section, "enabled", 0) == 1));
    json_object_object_add(item, "use_ipv6", json_object_new_int(uci_option_int(ctx, section, "use_ipv6", 0) == 1));
    json_object_object_add(item, "service_name", json_object_new_string(uci_option_string(ctx, section, "service_name")));
    json_object_object_add(item, "domain", json_object_new_string(uci_option_string(ctx, section, "domain")));
    json_object_object_add(item, "lookup_host", json_object_new_string(uci_option_string(ctx, section, "lookup_host")));
    json_object_object_add(item, "username", json_object_new_string(uci_option_string(ctx, section, "username")));
    json_object_object_add(item, "has_password", json_object_new_int(password[0] != '\0'));
    json_object_object_add(item, "param_enc", json_object_new_string(uci_option_string(ctx, section, "param_enc")));
    json_object_object_add(item, "param_opt", json_object_new_string(uci_option_string(ctx, section, "param_opt")));
    json_object_object_add(item, "running", json_object_new_int(section_running(runtime_dir, section->e.name)));
    json_object_object_add(item, "current_ip", json_object_new_string(current_ip));
    json_object_object_add(item, "last_update", json_object_new_int64(section_last_update(runtime_dir, section->e.name)));
    return item;
}

struct json_object *fwx_api_get_ddns_providers(struct json_object *req_obj)
{
    struct json_object *use_ipv6_obj = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *providers = json_object_new_array();
    int use_ipv6 = 0;

    if (req_obj && json_object_object_get_ex(req_obj, "use_ipv6", &use_ipv6_obj))
        use_ipv6 = json_object_get_int(use_ipv6_obj) == 1;
    append_providers_from_dir(providers, "/usr/share/ddns/custom", use_ipv6);
    append_providers_from_dir(providers, "/usr/share/ddns/default", use_ipv6);
    json_object_array_sort(providers, compare_provider_items);
    json_object_object_add(data, "providers", providers);
    json_object_object_add(data, "use_ipv6", json_object_new_int(use_ipv6));
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data);
}

struct json_object *fwx_api_get_ddns_services(struct json_object *req_obj)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *package = NULL;
    struct uci_element *element;
    struct json_object *data = json_object_new_object();
    struct json_object *services = json_object_new_array();
    char runtime_dir[256];

    (void)req_obj;
    if (!ctx || uci_load(ctx, DDNS_CONFIG, &package) != UCI_OK) {
        if (ctx)
            uci_free_context(ctx);
        json_object_put(data);
        json_object_put(services);
        return ddns_error("failed to load ddns configuration");
    }
    get_runtime_dir(ctx, package, runtime_dir, sizeof(runtime_dir));
    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (strcmp(section->type, "service") == 0)
            json_object_array_add(services, service_to_json(ctx, section, runtime_dir));
    }
    json_object_object_add(data, "services", services);
    uci_unload(ctx, package);
    uci_free_context(ctx);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int get_json_string(struct json_object *object, const char *name,
                           const char **value, int required)
{
    struct json_object *item = NULL;

    if (!json_object_object_get_ex(object, name, &item))
        return required ? -1 : 0;
    if (!json_object_is_type(item, json_type_string))
        return -1;
    *value = json_object_get_string(item);
    return 0;
}

static int generate_section_id(struct uci_context *ctx, struct uci_package *package,
                               char *buffer, size_t length)
{
    unsigned int suffix;
    time_t now = time(NULL);

    for (suffix = 0; suffix < 1000; suffix++) {
        snprintf(buffer, length, "fwxddns_%lld_%u", (long long)now, suffix);
        if (!uci_lookup_section(ctx, package, buffer))
            return 0;
    }
    return -1;
}

struct json_object *fwx_api_save_ddns_service(struct json_object *req_obj)
{
    struct json_object *enabled_obj = NULL;
    struct json_object *ipv6_obj = NULL;
    struct uci_context *ctx = NULL;
    struct uci_package *package = NULL;
    struct uci_section *section = NULL;
    ddns_provider_info_t provider;
    const char *id = "";
    const char *name = NULL;
    const char *service_name = NULL;
    const char *domain = NULL;
    const char *lookup_host = NULL;
    const char *username = "";
    const char *password = "";
    const char *param_enc = "";
    const char *param_opt = "";
    char name_buffer[64];
    char id_buffer[64];
    int enabled, use_ipv6, created = 0, action_result;

    if (!req_obj || !json_object_is_type(req_obj, json_type_object) ||
        get_json_string(req_obj, "name", &name, 1) != 0 ||
        get_json_string(req_obj, "service_name", &service_name, 1) != 0 ||
        get_json_string(req_obj, "domain", &domain, 1) != 0 ||
        get_json_string(req_obj, "lookup_host", &lookup_host, 1) != 0 ||
        get_json_string(req_obj, "id", &id, 0) != 0 ||
        get_json_string(req_obj, "username", &username, 0) != 0 ||
        get_json_string(req_obj, "password", &password, 0) != 0 ||
        get_json_string(req_obj, "param_enc", &param_enc, 0) != 0 ||
        get_json_string(req_obj, "param_opt", &param_opt, 0) != 0 ||
        !json_object_object_get_ex(req_obj, "enabled", &enabled_obj) ||
        !json_object_object_get_ex(req_obj, "use_ipv6", &ipv6_obj))
        return ddns_error("invalid request");
    enabled = json_object_get_int(enabled_obj);
    use_ipv6 = json_object_get_int(ipv6_obj);
    snprintf(name_buffer, sizeof(name_buffer), "%s", name);
    trim_string(name_buffer);
    if (!name_buffer[0] || strlen(name) > 63 || has_control(name_buffer) ||
        (enabled != 0 && enabled != 1) || (use_ipv6 != 0 && use_ipv6 != 1) ||
        !valid_domain(domain) || !valid_lookup_host(lookup_host) ||
        strlen(username) > 255 || strlen(password) > 512 ||
        strlen(param_enc) > 512 || strlen(param_opt) > 512 ||
        has_control(username) || has_control(password) ||
        has_control(param_enc) || has_control(param_opt) ||
        !service_name[0] || strlen(service_name) > 127 || has_control(service_name))
        return ddns_error("invalid service settings");
    if (!find_provider(service_name, use_ipv6, &provider))
        return ddns_error("provider is not installed or does not support this address type");
    if ((provider.require_username && !username[0]) ||
        (provider.require_param_enc && !param_enc[0]))
        return ddns_error("required provider fields are missing");

    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, DDNS_CONFIG, &package) != UCI_OK) {
        if (ctx)
            uci_free_context(ctx);
        return ddns_error("failed to load ddns configuration");
    }
    if (id && id[0]) {
        if (!valid_section_id(id) || !(section = uci_lookup_section(ctx, package, id)) ||
            strcmp(section->type, "service") != 0) {
            uci_unload(ctx, package);
            uci_free_context(ctx);
            return ddns_error("service does not exist");
        }
    } else {
        struct uci_ptr ptr;

        if (generate_section_id(ctx, package, id_buffer, sizeof(id_buffer)) != 0 ||
            uci_add_section(ctx, package, "service", &section) != UCI_OK) {
            uci_unload(ctx, package);
            uci_free_context(ctx);
            return ddns_error("failed to create service");
        }
        memset(&ptr, 0, sizeof(ptr));
        ptr.p = package;
        ptr.s = section;
        ptr.section = section->e.name;
        ptr.value = id_buffer;
        if (uci_rename(ctx, &ptr) != UCI_OK) {
            uci_unload(ctx, package);
            uci_free_context(ctx);
            return ddns_error("failed to create service");
        }
        section = uci_lookup_section(ctx, package, id_buffer);
        id = id_buffer;
        created = 1;
    }
    if (provider.require_password && !password[0] &&
        !uci_option_string(ctx, section, "password")[0]) {
        if (created) {
            struct uci_ptr ptr = { .p = package, .s = section };
            uci_delete(ctx, &ptr);
        }
        uci_unload(ctx, package);
        uci_free_context(ctx);
        return ddns_error("password is required");
    }

    if (set_option(ctx, package, section, "profile_name", name_buffer) != UCI_OK ||
        set_option(ctx, package, section, "enabled", enabled ? "1" : "0") != UCI_OK ||
        set_option(ctx, package, section, "use_ipv6", use_ipv6 ? "1" : "0") != UCI_OK ||
        set_option(ctx, package, section, "service_name", service_name) != UCI_OK ||
        set_option(ctx, package, section, "domain", domain) != UCI_OK ||
        set_option(ctx, package, section, "lookup_host", lookup_host) != UCI_OK ||
        set_option(ctx, package, section, "username", username) != UCI_OK ||
        set_option(ctx, package, section, "interface", use_ipv6 ? "wan6" : "wan") != UCI_OK ||
        set_option(ctx, package, section, "ip_source", "network") != UCI_OK ||
        set_option(ctx, package, section, "ip_network", use_ipv6 ? "wan6" : "wan") != UCI_OK ||
        set_option(ctx, package, section, "use_https", provider.use_https ? "1" : "0") != UCI_OK ||
        (password[0] && set_option(ctx, package, section, "password", password) != UCI_OK) ||
        (provider.require_param_enc && set_option(ctx, package, section, "param_enc", param_enc) != UCI_OK) ||
        (provider.require_param_opt && set_option(ctx, package, section, "param_opt", param_opt) != UCI_OK) ||
        (!provider.require_param_enc && delete_option(ctx, package, section, "param_enc") != UCI_OK) ||
        (!provider.require_param_opt && delete_option(ctx, package, section, "param_opt") != UCI_OK) ||
        uci_commit(ctx, &package, false) != UCI_OK) {
        uci_unload(ctx, package);
        uci_free_context(ctx);
        return ddns_error("failed to save ddns configuration");
    }
    uci_unload(ctx, package);
    uci_free_context(ctx);
    action_result = run_ddns_action(enabled ? "restart" : "stop", id);
    if (action_result != 0) {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "saved", json_object_new_int(1));
        json_object_object_add(data, "applied", json_object_new_int(0));
        json_object_object_add(data, "id", json_object_new_string(id));
        json_object_object_add(data, "message", json_object_new_string("configuration saved but service action failed"));
        return fwx_gen_api_response_data(API_CODE_ERROR, data);
    }
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "saved", json_object_new_int(1));
        json_object_object_add(data, "applied", json_object_new_int(1));
        json_object_object_add(data, "id", json_object_new_string(id));
        return fwx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
}

struct json_object *fwx_api_delete_ddns_service(struct json_object *req_obj)
{
    struct json_object *id_obj = NULL;
    struct uci_context *ctx;
    struct uci_package *package = NULL;
    struct uci_section *section;
    struct uci_ptr ptr;
    const char *id;
    int action_result;

    if (!req_obj || !json_object_object_get_ex(req_obj, "id", &id_obj) ||
        !json_object_is_type(id_obj, json_type_string))
        return ddns_error("invalid request");
    id = json_object_get_string(id_obj);
    if (!valid_section_id(id))
        return ddns_error("invalid service id");
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, DDNS_CONFIG, &package) != UCI_OK) {
        if (ctx)
            uci_free_context(ctx);
        return ddns_error("failed to load ddns configuration");
    }
    section = uci_lookup_section(ctx, package, id);
    if (!section || strcmp(section->type, "service") != 0) {
        uci_unload(ctx, package);
        uci_free_context(ctx);
        return ddns_error("service does not exist");
    }
    action_result = run_ddns_action("stop", id);
    memset(&ptr, 0, sizeof(ptr));
    ptr.p = package;
    ptr.s = section;
    if (uci_delete(ctx, &ptr) != UCI_OK || uci_commit(ctx, &package, false) != UCI_OK) {
        uci_unload(ctx, package);
        uci_free_context(ctx);
        return ddns_error("failed to delete service");
    }
    uci_unload(ctx, package);
    uci_free_context(ctx);
    if (action_result != 0) {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "saved", json_object_new_int(1));
        json_object_object_add(data, "applied", json_object_new_int(0));
        json_object_object_add(data, "message", json_object_new_string("service deleted but stop action failed"));
        return fwx_gen_api_response_data(API_CODE_ERROR, data);
    }
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}

struct json_object *fwx_api_update_ddns_service(struct json_object *req_obj)
{
    struct json_object *id_obj = NULL;
    struct uci_context *ctx;
    struct uci_package *package = NULL;
    struct uci_section *section;
    const char *id;

    if (!req_obj || !json_object_object_get_ex(req_obj, "id", &id_obj) ||
        !json_object_is_type(id_obj, json_type_string))
        return ddns_error("invalid request");
    id = json_object_get_string(id_obj);
    if (!valid_section_id(id))
        return ddns_error("invalid service id");
    ctx = uci_alloc_context();
    if (!ctx || uci_load(ctx, DDNS_CONFIG, &package) != UCI_OK) {
        if (ctx)
            uci_free_context(ctx);
        return ddns_error("failed to load ddns configuration");
    }
    section = uci_lookup_section(ctx, package, id);
    if (!section || strcmp(section->type, "service") != 0) {
        uci_unload(ctx, package);
        uci_free_context(ctx);
        return ddns_error("service does not exist");
    }
    uci_unload(ctx, package);
    uci_free_context(ctx);
    if (run_ddns_action("restart", id) != 0)
        return ddns_error("failed to update ddns service");
    return fwx_gen_api_response_data(API_CODE_SUCCESS, NULL);
}
