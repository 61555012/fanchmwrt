module("luci.controller.fwx_traffic_stat", package.seeall)

function index()
    entry({"admin", "fwx_monitor"}, firstchild(), _("System Monitor"), 12).dependent = true
    entry({"admin", "fwx_monitor", "traffic_stat"}, template("fwx_traffic_stat/traffic_stat"), _("Traffic Statistics"), 53).dependent = true
    entry({"admin", "traffic_stat_api", "get_today_traffic"}, call("get_today_traffic")).leaf = true
    entry({"admin", "traffic_stat_api", "get_history_traffic"}, call("get_history_traffic")).leaf = true
end

local function write_response(resp_obj, fallback)
    luci.http.prepare_content("application/json")
    if resp_obj and resp_obj.code == 2000 and resp_obj.data then
        luci.http.write_json(resp_obj.data)
    else
        luci.http.write_json(fallback)
    end
end

--[[
    硬件加速下的今日分时流量：直接取 client-rates 采样器的 24 个小时桶。
    fwx 原生的 get_global_traffic_stats 走 conntrack 计数，
    被 HNAT offload 的流量不会出现在里面，所以这里优先用自己的数据。
]]
function get_today_traffic()
    local util = require "luci.util"
    local cr = require "luci.crstat"

    local snap = cr.snapshot()

    if snap and type(snap.hourly) == "table" then
        local hours = {}

        for h = 0, 23 do
            local v = snap.hourly[h + 1] or {}

            hours[#hours + 1] = {
                hour = h,
                traffic = {
                    up_bytes = tonumber(v.up) or 0,
                    down_bytes = tonumber(v.down) or 0
                }
            }
        end

        luci.http.prepare_content("application/json")
        luci.http.write_json({
            date = cr.daystart(),
            is_today = 1,
            hourly_traffic = hours,
            source = "client-rates"
        })
        return
    end

    local req_obj = {
        api = "get_global_traffic_stats",
        data = {}
    }

    write_response(util.ubus("fwx", "common", req_obj), {
        date = 0,
        is_today = 1,
        hourly_traffic = {}
    })
end

function get_history_traffic()
    local util = require "luci.util"
    local cr = require "luci.crstat"

    local days = tonumber(luci.http.formvalue("days")) or 30
    if days < 1 then days = 1 end
    if days > 365 then days = 365 end

    local snap = cr.snapshot()

    if snap then
        local list = {}
        local seen = {}

        if type(snap.hist) == "table" then
            for d, v in pairs(snap.hist) do
                list[#list + 1] = {
                    date_str = d,
                    up_bytes = tonumber(v.up) or 0,
                    down_bytes = tonumber(v.down) or 0
                }
                seen[d] = true
            end
        end

        -- 今天还没写进历史，用 24 个小时桶累加
        local dstr = os.date("%Y-%m-%d")

        if not seen[dstr] then
            local tu, td = 0, 0

            if type(snap.hourly) == "table" then
                for _, v in ipairs(snap.hourly) do
                    tu = tu + (tonumber(v.up) or 0)
                    td = td + (tonumber(v.down) or 0)
                end
            end

            list[#list + 1] = {
                date_str = dstr,
                up_bytes = tu,
                down_bytes = td,
                is_today = 1
            }
        end

        for _, it in ipairs(list) do
            it.total_bytes = it.up_bytes + it.down_bytes
        end

        table.sort(list, function(a, b) return a.date_str < b.date_str end)

        while #list > days do
            table.remove(list, 1)
        end

        luci.http.prepare_content("application/json")
        luci.http.write_json({
            days = days,
            list = list,
            source = "client-rates"
        })
        return
    end

    local req_obj = {
        api = "get_history_traffic_stats",
        data = {
            days = days
        }
    }

    write_response(util.ubus("fwx", "common", req_obj), {
        days = days,
        list = {}
    })
end
