--[[
    crstat —— 读取 client-rates 采样器产物，供 fwx 页面替换数据源

    采样器（/etc/init.d/client-rates）在硬件加速下用
    conntrack + HNAT all_entry 双源统计，结果写 /tmp/client-rates.json。
    这里只负责把它翻译成 fwx 各 API 期望的结构。
]]

module("luci.crstat", package.seeall)

local jsonc = require "luci.jsonc"

local SNAP = "/tmp/client-rates.json"

-- 采样结果，读不到就返回 nil（调用方回退到原 fwx 数据）
function snapshot()
	local f = io.open(SNAP, "r")
	if not f then
		return nil
	end

	local s = f:read("*a")
	f:close()

	if not s or #s < 16 then
		return nil
	end

	local ok, d = pcall(jsonc.parse, s)
	if not ok or type(d) ~= "table" or type(d.ts) ~= "number" then
		return nil
	end

	return d
end

-- 采样器的 key 是大写 MAC，fwx 用小写，统一到大写再查
function macup(mac)
	return (tostring(mac or ""):upper())
end

-- MAC(大写) -> 主机名，来自 DHCP 租约
function hosts()
	local m = {}
	local f = io.open("/tmp/dhcp.leases", "r")

	if f then
		for line in f:lines() do
			local _, mac, _, name = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
			if mac and name and name ~= "*" and name ~= "" then
				m[mac:upper()] = name
			end
		end
		f:close()
	end

	return m
end

-- 当天 0 点时间戳
function daystart()
	local t = os.date("*t")
	t.hour, t.min, t.sec = 0, 0, 0
	return os.time(t)
end

-- 把 { up, down } 统一成数字，缺字段补 0
function pair(v)
	if type(v) ~= "table" then
		return 0, 0
	end
	return tonumber(v.up) or 0, tonumber(v.down) or 0
end

-- 设备是否在采样数据里出现过
function has_dev(cr, mac)
	return cr and cr.rates and cr.rates[macup(mac)] ~= nil
end

-- 该 MAC 的实时速率
function rates(cr, mac)
	local r = cr and cr.rates and cr.rates[macup(mac)]
	if type(r) ~= "table" then
		return 0, 0
	end
	return tonumber(r.upload) or 0, tonumber(r.download) or 0
end

-- 该 MAC 的今日流量
function today(cr, mac)
	local t = cr and cr.today and cr.today[macup(mac)]
	return pair(t)
end

-- 该 MAC 的 IP / 接口 / 无线属性
function devinfo(cr, mac)
	local d = cr and cr.dev and cr.dev[macup(mac)]
	if type(d) ~= "table" then
		return nil
	end
	return d
end

-- 全网今日流量合计
function today_total(cr)
	local up, down = 0, 0

	if cr and type(cr.today) == "table" then
		for _, v in pairs(cr.today) do
			local u, d = pair(v)
			up   = up + u
			down = down + d
		end
	end

	return up, down
end

--[[
    把采样器数据覆盖到一条 fwx 用户记录上（终端列表 / 今日排行都用）。
    fwx 这组字段依赖 conntrack 的 acct，HNAT 分载后基本不再变化，必须替换。
    只覆盖流量类字段，主机名、昵称、应用、信号强度等仍然保留 fwx 的。
]]
function patch_user(cr, u)
	if not cr or type(u) ~= "table" then
		return false
	end

	local mac = macup(u.mac)
	if mac == "" then
		return false
	end

	-- 采样器没见过这台设备时不要清零，保持 fwx 原值；
	-- 但「在线」状态要纠正：fwx 的 ARP 残留会把拔电/休眠设备一直标成在线，
	-- 页面就会出现「在线但流量恒为 0」的幽灵终端。
	if not (cr.dev and cr.dev[mac]) and not (cr.rates and cr.rates[mac]) then
		u.online = 0
		u.active = 0
		return false
	end

	u.online = 1

	local ru, rd = rates(cr, mac)
	local tu, td = today(cr, mac)

	u.up_rate          = ru
	u.down_rate        = rd
	u.today_up_bytes   = tu
	u.today_down_bytes = td

	-- 详情页顶部要的今日在线/活跃时长
	local dv = (cr.devDaily and cr.devDaily[mac] and cr.devDaily[mac][os.date("%Y-%m-%d")]) or nil
	if type(dv) == "table" then
		u.today_online_time = tonumber(dv.online) or 0
		u.today_active_time = tonumber(dv.active) or 0
	end

	local d = devinfo(cr, mac)
	if d then
		if (u.ip == nil or u.ip == "") and d.ip then
			u.ip = d.ip
		end
		if (u.ipv6 == nil or u.ipv6 == "") and type(d.ip6) == "table" and d.ip6[1] then
			u.ipv6 = d.ip6[1]
		end
	end

	return true
end

-- 对一整个 list 批量打补丁
function patch_users(cr, list)
	if not cr or type(list) ~= "table" then
		return
	end

	for _, u in ipairs(list) do
		patch_user(cr, u)
	end
end

-- 上下线记录（采样器生成），已按时间倒序
function records(cr)
	local r = cr and cr.records
	if type(r) ~= "table" then
		return {}
	end
	return r
end

-- 该 MAC 最近一次会话（在线中才有）
function session_of(cr, mac)
	local recs = records(cr)
	local m = macup(mac)

	for _, e in ipairs(recs) do
		if macup(e.mac) == m and tonumber(e.action) == 0 then
			return e
		end
	end

	return nil
end

-- 单机今日分时：mac -> { "0".."23": { up, down } }
function dev_hourly(cr, mac)
	local h = cr and cr.devHourly and cr.devHourly[macup(mac)]
	if type(h) ~= "table" then
		return {}
	end
	return h
end

-- 单机每日历史：mac -> { "YYYY-MM-DD": { up, down, active, online } }
function dev_daily(cr, mac)
	local d = cr and cr.devDaily and cr.devDaily[macup(mac)]
	if type(d) ~= "table" then
		return {}
	end
	return d
end

-- 终端详情页的上下线事件列表（字段名和 fwx 原版保持一致）
function build_online_offline(cr, mac)
	local out = {}
	local want = (mac and mac ~= "") and macup(mac) or nil

	for _, e in ipairs(records(cr)) do
		if not want or macup(e.mac) == want then
			local ts  = tonumber(e.ts) or 0
			local dur = tonumber(e.dur) or 0

			out[#out + 1] = {
				type      = tonumber(e.action) or 0,
				timestamp = ts,
				time_str  = os.date("%Y-%m-%d %H:%M:%S", ts),
				duration  = dur
			}
		end
	end

	return out
end

--[[
    终端详情页 · 今日 24 小时分时图。
    采样器只按小时记 up/down，应用维度（apps）仍然沿用 fwx 的，
    所以这里把两边按小时对齐后拼起来。
]]
function patch_hourly(cr, mac, data)
	local h = dev_hourly(cr, mac)

	local old = {}
	if type(data) == "table" and type(data.hourly_stats) == "table" then
		for _, v in ipairs(data.hourly_stats) do
			if type(v) == "table" and v.hour ~= nil then
				old[tonumber(v.hour) or 0] = v
			end
		end
	end

	local list = {}

	for i = 0, 23 do
		-- JSON 解析后对象 key 是字符串，不能用数字索引
		local b = h[tostring(i)]
		local up, down = pair(b)

		list[#list + 1] = {
			hour    = i,
			traffic = { up_bytes = up, down_bytes = down },
			apps    = (old[i] and type(old[i].apps) == "table") and old[i].apps or {}
		}
	end

	data.hourly_stats = list
	data.mac          = mac
	data.is_today     = 1

	return data
end

--[[
    终端详情页 · 历史每日（固定 30 条，页面会校验长度）。
    采样器只保留有数据的日子，这里补齐成连续 30 天，缺的那天 available=false。
]]
function build_daily(cr, mac, days)
	days = tonumber(days) or 30

	local dd  = dev_daily(cr, mac)
	local now = os.time()
	local list = {}

	for i = days - 1, 0, -1 do
		local t = os.date("*t", now - i * 86400)
		local date = string.format("%04d-%02d-%02d", t.year, t.month, t.day)
		local v = dd[date]

		list[#list + 1] = {
			date             = date,
			available        = (v ~= nil),
			up_bytes         = v and (tonumber(v.up) or 0) or 0,
			down_bytes       = v and (tonumber(v.down) or 0) or 0,
			active_seconds   = v and (tonumber(v.active) or 0) or 0,
			online_seconds   = v and (tonumber(v.online) or 0) or 0,
			category_seconds = {},   -- 应用分类时长只有 fwx 有，加速下也是空的
			top_apps         = {}
		}
	end

	return {
		mac        = mac,
		start_date = list[1] and list[1].date,
		list       = list,
		source     = "client-rates"
	}
end
