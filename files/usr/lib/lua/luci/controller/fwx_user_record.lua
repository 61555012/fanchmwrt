module("luci.controller.fwx_user_record", package.seeall)

function index()
    local online_offline_node

    entry({"admin", "fwx_monitor"}, firstchild(), _("System Monitor"), 12).dependent = true
    entry({"admin", "fwx_monitor", "user_record"}, alias("admin", "fwx_monitor", "user_record", "online_offline"), _("User Records"), 52).dependent = true
    online_offline_node = entry({"admin", "fwx_monitor", "user_record", "online_offline"}, template("fwx_user_record/user_record"), _("Online/Offline Records"), 10)
    online_offline_node.leaf = true
    online_offline_node.dependent = true
    entry({"admin", "fwx_monitor", "user_record", "user_record"}, alias("admin", "fwx_monitor", "user_record", "online_offline"), nil, 11).leaf = true
    entry({"admin", "user_record_api", "get_user_records"}, call("get_user_records")).leaf = true
end

--[[
    上下线记录改用 client-rates 采样器产生。

    原因：fwx 原来的记录来自 conntrack acct，它只在设备上线/下线那一刻
    快照一次；HNAT 之下这条流早就不经过 netfilter 了，于是每条记录的
    up_bytes/down_bytes 都是 0，「终端记录」永远没有新内容。

    采样器自己跟踪 ARP 表里的设备：新 MAC 出现记 online，消失超过 3 分钟
    记 offline，流量按会话累计。在线的设备会实时刷新当前会话量。
]]
local function build_from_snapshot(page, page_size, mac_filter, start_time, end_time)
    local cr = require "luci.crstat"
    local snap = cr.snapshot()

    if not snap then
        return nil
    end

    local hm  = cr.hosts()
    local raw = cr.records(snap)
    local out = {}

    mac_filter = (mac_filter and mac_filter ~= "") and mac_filter:lower() or nil

    for _, e in ipairs(raw) do
        local mac  = tostring(e.mac or "")
        local ts   = tonumber(e.ts) or 0
        local keep = true

        if mac_filter and mac:lower():find(mac_filter, 1, true) == nil then
            keep = false
        end
        if keep and start_time > 0 and ts < start_time then
            keep = false
        end
        if keep and end_time > 0 and ts > end_time then
            keep = false
        end

        if keep then
            local action = tonumber(e.action) or 0

            out[#out + 1] = {
                timestamp       = ts,
                time_str        = os.date("%Y-%m-%d %H:%M:%S", ts),
                action          = action,
                action_str      = (action == 0) and "online" or "offline",
                mac             = mac:lower(),
                nickname        = "",
                hostname        = hm[tostring(mac):upper()] or "",
                up_bytes        = tonumber(e.up) or 0,
                down_bytes      = tonumber(e.down) or 0,
                online_duration = tonumber(e.dur) or 0,
                active_duration = tonumber(e.active) or 0,
                recent_apps     = {}
            }
        end
    end

    local total      = #out
    local total_page = math.max(1, math.ceil(total / page_size))
    local from       = (page - 1) * page_size + 1
    local list       = {}

    for i = from, math.min(from + page_size - 1, total) do
        list[#list + 1] = out[i]
    end

    return {
        total_num  = total,
        total_page = total_page,
        page       = page,
        page_size  = page_size,
        list       = list,
        source     = "client-rates"
    }
end

function get_user_records()
    local util = require "luci.util"
    local mac = luci.http.formvalue("mac")
    local start_time = tonumber(luci.http.formvalue("start_time") or "0") or 0
    local end_time = tonumber(luci.http.formvalue("end_time") or "0") or 0
    local page = tonumber(luci.http.formvalue("page") or "1") or 1
    local page_size = tonumber(luci.http.formvalue("page_size") or "15") or 15

    luci.http.prepare_content("application/json")

    if page < 1 then page = 1 end
    if page_size < 1 or page_size > 200 then page_size = 15 end

    local mine = build_from_snapshot(page, page_size, mac, start_time, end_time)

    if mine then
        luci.http.write_json(mine)
        return
    end

    -- 采样器没起来时回退到 fwx 原生结果
    local req_obj = {
        api = "get_user_records",
        data = {
            mac = mac,
            start_time = start_time,
            end_time = end_time,
            page = page,
            page_size = page_size
        }
    }

    local resp_obj = util.ubus("fwx", "common", req_obj)
    if resp_obj and resp_obj.code == 2000 and resp_obj.data then
        luci.http.write_json(resp_obj.data)
    else
        luci.http.write_json({
            total_num = 0,
            total_page = 1,
            page = page,
            page_size = page_size,
            list = {}
        })
    end
end
