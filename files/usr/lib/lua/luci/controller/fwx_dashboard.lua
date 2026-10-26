module("luci.controller.fwx_dashboard", package.seeall)

function index()
	entry({"admin", "fwx_dashboard"}, cbi("fwx_dashboard/dashboard", {hideapplybtn=true, hidesavebtn=true, hideresetbtn=true}),
	 _("Dashboard"), 1).leaf = true
	
	entry({"admin", "dashboard_api", "get_dashboard_common"}, call("get_dashboard_common")).leaf = true
	entry({"admin", "dashboard_api", "get_init_status"}, call("get_init_status")).leaf = true
	entry({"admin", "dashboard_api", "set_init_status"}, call("set_init_status")).leaf = true
	entry({"admin", "dashboard_api", "get_daily_top_users"}, call("get_daily_top_users")).leaf = true
	entry({"admin", "dashboard_api", "get_active_users"}, call("get_active_users")).leaf = true
	entry({"admin", "dashboard_api", "get_app_type_stats"}, call("get_app_type_stats")).leaf = true
end

function get_dashboard_common()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_dashboard_common"
	req_obj.CopyRight = "www.fanchmwrt.com"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		-- WAN 实时速率与在线数也改用采样器数据，
		-- 否则 HNAT 分载后 fwx 这边的曲线会一直贴着 0 走
		local cr = require "luci.crstat"
		local snap = cr.snapshot()

		if snap then
			local it = resp_obj.data.interface_traffic

			if type(it) == "table" and type(it.traffic) == "table" and #it.traffic > 0 then
				local last = it.traffic[#it.traffic]

				if type(last) == "table" then
					last.up   = tonumber(snap.wan and snap.wan.up) or last.up
					last.down = tonumber(snap.wan and snap.wan.down) or last.down
				end
			end

			local ss = resp_obj.data.system_status

			if type(ss) == "table" then
				if type(snap.summary) == "table" then
					ss.online_user_count = tonumber(snap.summary.online) or ss.online_user_count
				end

				-- 顶部「今日流量」卡片：fwx 这个字段单位是 KB，
				-- 来源同样是 conntrack acct，加速后基本不动，换成采样器合计
				if type(ss.flow) == "table" then
					local fu, fd = cr.today_total(snap)

					ss.flow.today_up   = math.floor(fu / 1024)
					ss.flow.today_down = math.floor(fd / 1024)
				end
			end
		end

		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			system_status = {},
			network_status = {},
			active_app = {total = 0, list = {}},
			interface_traffic = {interface = "wan", traffic = {}}
		})
	end
end

function get_init_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "get_init_status"
	req_obj.data = {}

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({init_status = 1})
	end
end

function set_init_status()
	local utl = require "luci.util"
	luci.http.prepare_content("application/json")

	local req_obj = {}
	req_obj.api = "set_init_status"
	req_obj.data = { init_status = 1 }

	local resp_obj = utl.ubus("fwx", "common", req_obj)
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({init_status = 0})
	end
end

--[[
	注意：fwx 后台的流量数据来自 nf_conntrack 的 acct 扩展。
	开启 MTK 硬件加速（HNAT）后，已被 PPE 接管的连接不再经过 netfilter，
	conntrack 里的字节数会停留在「绑定」那一刻，于是 fwx 统计出的今日流量
	往往只有实际值的百分之几。下面两个接口因此改为用 client-rates 采样器的
	数据覆盖数值部分，其余字段（rssi / band / 无线接口 / 应用识别）仍保留
	fwx 的结果。
]]

function get_daily_top_users()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	local cr = require "luci.crstat"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_daily_top_users"
	req_obj.data = {}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	local data = (resp_obj and resp_obj.code == 2000 and resp_obj.data) or {
		date = cr.daystart(),
		total_count = 0,
		users = {}
	}

	local snap = cr.snapshot()

	if snap then
		local hm = cr.hosts()
		local seen = {}

		data.users = data.users or {}

		for _, u in ipairs(data.users) do
			local mac = tostring(u.mac or ""):upper()

			if mac ~= "" then
				seen[mac] = true

				local up, down = cr.today(snap, mac)
				u.up_bytes    = up
				u.down_bytes  = down
				u.total_bytes = up + down

				local d = cr.devinfo(snap, mac)
				if d and d.ip and (u.ip == nil or u.ip == "") then
					u.ip = d.ip
				end
				if hm[mac] and (u.hostname == nil or u.hostname == "") then
					u.hostname = hm[mac]
				end
			end
		end

		if type(snap.dev) == "table" then
			for mac, d in pairs(snap.dev) do
				if not seen[mac] then
					local up, down = cr.today(snap, mac)

					if up + down > 0 then
						table.insert(data.users, {
							mac = mac,
							ip = d.ip or "",
							hostname = hm[mac] or "",
							nickname = "",
							up_bytes = up,
							down_bytes = down,
							total_bytes = up + down
						})
					end
				end
			end
		end

		table.sort(data.users, function(a, b)
			return (tonumber(a.total_bytes) or 0) > (tonumber(b.total_bytes) or 0)
		end)

		data.total_count = #data.users
		data.date = cr.daystart()
		data.source = "client-rates"
	end
	
	luci.http.write_json(data)
end

function get_active_users()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	local cr = require "luci.crstat"
	
	luci.http.prepare_content("application/json")
	
	local req_obj = {}
	req_obj.api = "get_active_users"
	req_obj.data = {}
	
	local count = luci.http.formvalue("count")
	if count then
		req_obj.data.count = tonumber(count) or 8
	else
		req_obj.data.count = 8
	end
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	local data = (resp_obj and resp_obj.code == 2000 and resp_obj.data) or {
		total_count = 0,
		users = {}
	}

	local snap = cr.snapshot()

	if snap then
		local hm = cr.hosts()
		local seen = {}

		data.users = data.users or {}

		for _, u in ipairs(data.users) do
			local mac = tostring(u.mac or ""):upper()

			if mac ~= "" then
				seen[mac] = true

				local ur, dr = cr.rates(snap, mac)
				u.up_rate   = ur
				u.down_rate = dr

				local tu, td = cr.today(snap, mac)
				u.today_up_bytes   = tu
				u.today_down_bytes = td

				local d = cr.devinfo(snap, mac)
				if d and d.ip then
					u.ip = d.ip
				end
				if hm[mac] and (u.hostname == nil or u.hostname == "") then
					u.hostname = hm[mac]
				end
			end
		end

		if type(snap.dev) == "table" then
			for mac, d in pairs(snap.dev) do
				if not seen[mac] then
					local ur, dr = cr.rates(snap, mac)
					local tu, td = cr.today(snap, mac)

					if ur + dr > 0 or tu + td > 0 then
						table.insert(data.users, {
							mac = mac,
							ip = d.ip or "",
							hostname = hm[mac] or "",
							nickname = "",
							up_rate = ur,
							down_rate = dr,
							rssi = 0,
							rx_rate = 0,
							tx_rate = 0,
							band = "",
							wifi_ifname = "",
							is_wireless = 0,
							terminal_type = "wired",
							today_up_bytes = tu,
							today_down_bytes = td,
							app = "",
							url = ""
						})
					end
				end
			end
		end

		data.total_count = #data.users
		data.source = "client-rates"
	end
	
	luci.http.write_json(data)
end

function get_app_type_stats()
	local json = require "luci.jsonc"
	local utl = require "luci.util"
	
	luci.http.prepare_content("application/json")
	
	local stat_type = luci.http.formvalue("type") or "hourly"
	
	local req_obj = {}
	req_obj.api = "get_global_app_type_stats"
	req_obj.data = {
		type = stat_type,
		limit = 10
	}
	
	local resp_obj = utl.ubus("fwx", "common", req_obj)
	
	if resp_obj and resp_obj.code == 2000 and resp_obj.data then
		luci.http.write_json(resp_obj.data)
	else
		luci.http.write_json({
			type = stat_type,
			limit = 10,
			total_count = 0,
			types = {}
		})
	end
end
