// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _FWX_FASTNAT_H_
#define _FWX_FASTNAT_H_

#include <json-c/json.h>

struct json_object *fwx_api_get_fastnat_status(struct json_object *req_obj);
struct json_object *fwx_api_get_fastnat_config(struct json_object *req_obj);
struct json_object *fwx_api_set_fastnat_config(struct json_object *req_obj);

#endif
