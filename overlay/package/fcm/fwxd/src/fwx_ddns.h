// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __FWX_DDNS_H__
#define __FWX_DDNS_H__

#include <json-c/json.h>

struct json_object *fwx_api_get_ddns_services(struct json_object *req_obj);
struct json_object *fwx_api_get_ddns_providers(struct json_object *req_obj);
struct json_object *fwx_api_save_ddns_service(struct json_object *req_obj);
struct json_object *fwx_api_delete_ddns_service(struct json_object *req_obj);
struct json_object *fwx_api_update_ddns_service(struct json_object *req_obj);

#endif
