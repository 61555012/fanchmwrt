'use strict';

/*
 * client-rates sampler —— 硬件加速(HNAT)下的逐设备流量统计
 *
 * 问题：MT7986 的 HNAT 把已学习的长连接交给 PPE 转发，包不再经过 netfilter，
 *       于是 /proc/net/nf_conntrack 里的 bytes 在「绑定」那一刻之后就冻结了。
 *       fwx（FanchmWrt 的流量系统）正是靠 nf_conntrack 的 acct 扩展计数，
 *       所以开了硬件加速后它的今日流量只有实际值的 1% 左右。
 *
 * 做法：双源合并
 *       ① conntrack —— 统计「没被 offload」的流（短连接、UDP、DNS…）
 *       ② HNAT all_entry —— 统计「已绑定 PPE」的流，state=BIND 的条目带硬件计数
 *       两条数据源互斥（同一条流只会落在其中一边），累加不会重复。
 *
 * 上下行拆分：all_entry 的 bytes 是双向合计，没有方向信息。
 *       对每条 BIND 流，尽量去 conntrack 里找同名条目，用它的 up:down 比例来摊；
 *       找不到就用全局比例。家庭网络以下行为主，误差可控。
 *
 * 输出：/tmp/client-rates.json（每 2 秒原子重写，ubus 只读这个文件）
 */

import { open, popen, writefile, rename } from 'fs';
import * as uloop from 'uloop';

const INTERVAL_MS = 2000;
const OUT         = '/tmp/client-rates.json';
const TMP         = '/tmp/client-rates.json.tmp';
const HIST_FILE   = '/tmp/client-rates-hist.json';
const TODAY_FILE  = '/tmp/client-rates-today.json';
/* /tmp 是内存盘，重装插件、重启、sysupgrade 都会清空，今日累计和历史会归零。
 * 真正的账本放 flash，15 分钟落一次（4 KB / 次，一天 96 次，对 NAND 无压力）。 */
const STATE_DIR   = '/etc/client-rates';
const STATE_FILE  = STATE_DIR + '/state.json';
const STATE_TMP   = STATE_DIR + '/state.json.tmp';
const STATE_S     = 900;
const DAY_TZ      = 8 * 3600;
const WINDOW_MS   = 6000;
const MIN_SPAN_MS = 1200;
const SAVE_S      = 15;   /* 今日累计落盘间隔，/tmp 是内存，写不磨损 flash */

const CT_PATH   = '/proc/net/nf_conntrack';
const HNAT_ENTRY = '/sys/kernel/debug/hnat/all_entry';
const HNAT_HOOK  = '/sys/kernel/debug/hnat/hook_toggle';

/* proto 数字 → conntrack 里的名字，用于两条数据源对齐 key */
const PROTO = { '1': 'icmp', '6': 'tcp', '17': 'udp', '58': 'ipv6-icmp', '132': 'sctp' };

let started  = time();
let flowsCt  = {};   /* conntrack key -> { b1, b2 } 上次原始字节 */
let flowsHw  = {};   /* hnat key      -> bytes    上次硬件计数 */
let seenCt   = {};   /* 本轮用到的 key，用于淘汰 */
let seenHw   = {};
let acc      = {};   /* mac -> { up, down } 服务启动以来的累计 */
let today    = {};   /* mac -> { up, down } 今日 */
let hourly   = [];   /* 24 个 { up, down } 全局今日分时 */
let hist     = {};   /* "YYYY-MM-DD" -> { up, down } 历史每日 */
let daykey   = 0;
let samples  = [];   /* [{ ts, snap }] 速率窗口 */
let lastSave = 0;
let lastState = 0;
let lastTs   = 0;
let ipmac    = {};   /* ip -> { mac, dev } */
let devmap   = {};   /* mac -> { ip4, ip6[], iface } */
let ctUp     = 0, ctDown = 0;      /* 全局 conntrack 累计，用于默认方向比例 */
let wan      = { rx: 0, tx: 0, prevRx: 0, prevTx: 0, rateUp: 0, rateDown: 0 };
let stat     = { ct: 0, hw: 0, orphan: 0, err: '' };
let lanPrefix = '192.168.2.';
let lastActive = {};   /* mac -> 最后一次见到流量的时间 */

/* 会话追踪：给「终端记录」提供上下线事件与单次在线流量。
 * ARP 表里出现新 MAC 记一条 online，消失超过 OFFLINE_S 秒记一条 offline。 */
let sess      = {};  /* mac -> { start, up, down, last, active, ev } */
let devHourly = {};  /* mac -> { hour: { up, down } } 今日分时（单机图表） */
let devDaily  = {};  /* mac -> { "YYYY-MM-DD": { up, down } } 近 40 天（单机历史） */
const DEV_DAYS = 40;
let events   = [];   /* 上下线事件，旧的在前，输出时倒序 */
const EV_MAX   = 300;
const OFFLINE_S = 180;    /* 从邻居表彻底消失后多久算离线 */
const OFFLINE_LONG = 600; /* 邻居表里还在但已 stale，多久算离线 */

/* 设备时区已经是 Asia/Shanghai，直接用 localtime，不要再加偏移 */
function dayKey() {
	const t = localtime(time());
	return t.year * 10000 + t.mon * 100 + t.mday;
}

function dateStr(ts) {
	const t = localtime(ts);
	return sprintf('%04d-%02d-%02d', t.year, t.mon, t.mday);
}

function hourNow() {
	return localtime(time()).hour;
}

/* 读一个 JSON 文件，失败返回 null（不抛异常）。
 * 注意：ucode 的函数在编译期绑定，被调用方必须定义在前面。 */
function readJson(path) {
	const fd = open(path, 'r');
	if (!fd)
		return null;

	const s = fd.read('all');
	fd.close();

	if (s == null || length(s) < 2)
		return null;

	const d = json(s);
	return (type(d) == 'object') ? d : null;
}

function initDay() {
	for (let i = 0; i < 24; i++)
		hourly[i] = { up: 0, down: 0 };

	daykey = dayKey();

	/* 先读 flash 上的账本（跨重启/重装），读不到再退回 /tmp 的临时快照 */
	let d2 = readJson(STATE_FILE);

	if (type(d2) != 'object')
		d2 = readJson(TODAY_FILE);

	if (type(d2) == 'object') {
		if (type(d2.hist) == 'object')
			hist = d2.hist;

		if (d2.day == daykey) {
			if (type(d2.today) == 'object') {
				for (let m, v in d2.today)
					if (type(v) == 'object')
						today[m] = { up: v.up ?? 0, down: v.down ?? 0 };
			}

			if (type(d2.hourly) == 'array' && length(d2.hourly) == 24)
				hourly = d2.hourly;

			if (type(d2.devHourly) == 'object')
				devHourly = d2.devHourly;
		}

		/* 每日历史跨天也要留 */
		if (type(d2.devDaily) == 'object')
			devDaily = d2.devDaily;
	}

	/* 兼容旧版单独存放的 hist 文件 */
	if (!length(keys(hist))) {
		const hd = readJson(HIST_FILE);
		if (type(hd) == 'object')
			hist = hd;
	}
}

function saveToday() {
	writefile(TODAY_FILE, sprintf('%J', {
		day: daykey, today: today, hourly: hourly,
		devHourly: devHourly, devDaily: devDaily
	}));
}

function saveHist() {
	writefile(HIST_FILE, sprintf('%J', hist));
}

/* 账本落 flash：先写 tmp 再 rename，掉电不会留半截文件。
 * 这是唯一写到 flash 的地方，靠 STATE_S 控制频率。 */
function saveState() {
	writefile(STATE_TMP, sprintf('%J', {
		day: daykey,
		today: today,
		hourly: hourly,
		devHourly: devHourly,
		devDaily: devDaily,
		hist: hist
	}));
	rename(STATE_TMP, STATE_FILE);
}

function rollDay() {
	const k = dayKey();
	if (k == daykey)
		return;

	/* 跨日：把昨天写进历史，清空今日 */
	let tu = 0, td = 0;
	for (let i = 0; i < 24; i++) {
		tu += hourly[i].up;
		td += hourly[i].down;
	}
	hist[dateStr(time() - 300)] = { up: tu, down: td };

	/* 只留最近 60 天 */
	const ks = sort(keys(hist));
	while (length(ks) > 60)
		delete hist[shift(ks)];

	initDay();
	for (let m in today)
		today[m] = { up: 0, down: 0 };

	/* 新的一个月/一天：单机分时清零，每日历史只留最近 DEV_DAYS 天 */
	for (let m in devHourly)
		devHourly[m] = {};

	for (let m, dd in devDaily) {
		const ks = sort(keys(dd));
		while (length(ks) > DEV_DAYS)
			delete dd[shift(ks)];
	}

	daykey = k;
	saveHist();
	saveToday();
	saveState();
	lastState = time();
}

function hnatOn() {
	const fd = open(HNAT_HOOK, 'r');
	if (!fd)
		return false;
	const s = trim(fd.read('line') ?? '');
	fd.close();
	return s == 'enabled' || s == '1';
}

/* TurboACC 是否打开了「HNAT 连接计数更新」（fastpath_mh_update_nfct） */
let nfctCache = { v: 0, t: 0 };

function updateNfct() {
	if (time() - nfctCache.t < 10)
		return nfctCache.v;

	const fd = open('/etc/config/turboacc', 'r');
	let v = 0;

	if (fd) {
		for (let line = fd.read('line'); length(line); line = fd.read('line')) {
			const t = split(trim(line), /\s+/);
			if (length(t) >= 3 && t[1] == 'fastpath_mh_update_nfct')
				v = (t[2] == "'1'" || t[2] == '"1"' || t[2] == '1') ? 1 : 0;
		}
		fd.close();
	}

	nfctCache = { v: v, t: time() };
	return v;
}

function hasFlag2(s) {
	if (substr(s, 0, 2) != '0x')
		return false;
	return (hex(substr(s, 2)) & 2) != 0;
}

function tokens(line) {
	let out = [];
	for (let t in split(trim(line), /\s+/))
		if (length(t))
			push(out, t);
	return out;
}

function field(toks, from, to, name) {
	const pfx = name + '=';
	for (let i = from; i < to; i++)
		if (substr(toks[i], 0, length(pfx)) == pfx)
			return substr(toks[i], length(pfx));
	return null;
}

/* 内网网段前缀，启动时从 uci 读一次 */
function initLanPrefix() {
	let ip = '';

	const f = popen('uci get network.lan.ipaddr 2>/dev/null');
	if (f) {
		ip = trim(f.read('line') ?? '');
		f.close();
	}

	if (ip == '') {
		const g = popen("/sbin/ip -4 addr show br-lan 2>/dev/null | grep -o 'inet [0-9.]*' | head -1 | cut -d' ' -f2");
		if (g) {
			ip = trim(g.read('line') ?? '');
			g.close();
		}
	}

	const p = split(ip, '.');
	if (length(p) == 4 && p[0] != '')
		lanPrefix = p[0] + '.' + p[1] + '.' + p[2] + '.';
}

/* 内网地址判定：IPv4 看前缀，IPv6 只看 ULA / 链路本地 */
function isLanIp(ip) {
	if (ip == null)
		return false;
	if (index(ip, ':') >= 0)
		return (substr(ip, 0, 3) == 'fd') || (substr(ip, 0, 5) == 'fe80:');
	return substr(ip, 0, length(lanPrefix)) == lanPrefix;
}

/* 只认内网桥上的邻居：eth1(WAN) 那侧的条目是上游路由，不是客户端 */
function isLan(dev) {
	return (dev == 'br-lan') || (substr(dev, 0, 3) == 'br-');
}

/* IP -> { mac, dev }，同时汇总 MAC -> { ip4, ip6[], iface } */
function readNeigh() {
	let map = {};
	devmap = {};

	let fd = open('/proc/net/arp', 'r');

	if (fd) {
		for (let line = fd.read('line'); length(line); line = fd.read('line')) {
			let t = tokens(line);
			if (length(t) != 6 || t[0] == 'IP')
				continue;

			/* /proc/net/arp 的 Flags 里 0x2 = ATF_COM（MAC 已解析完整）。
			 * 没有这一位说明 ARP 解析失败，MAC 字段是上一手残留 —— 不能当在线设备。
			 * 之前只挡全零 MAC，导致拔电/休眠的手机一直显示在线、在线时长还在涨，
			 * 而流量恒为 0，看起来就像「WiFi 统计不到」。 */
			if (t[3] == '00:00:00:00:00:00')
				continue;
			if (!hasFlag2(t[2]))
				continue;
			if (!isLan(t[5]))
				continue;

			const mac = uc(t[3]);
			map[t[0]] = { mac: mac, dev: t[5], reach: hasFlag2(t[2]) };

			let d = devmap[mac];
			if (!d)
				d = devmap[mac] = { ip4: null, ip6: [], iface: t[5], reach: 0 };
			if (!d.ip4)
				d.ip4 = t[0];
			if (hasFlag2(t[2]))
				d.reach = 1;
		}
		fd.close();
	}

	let f6 = popen('/sbin/ip -6 neigh show 2>/dev/null');
	if (f6) {
		for (let line = f6.read('line'); length(line); line = f6.read('line')) {
			let t = tokens(line);
			if (length(t) >= 5 && t[1] == 'dev' && t[3] == 'lladdr' && isLan(t[2])) {
				const mac = uc(t[4]);
				map[lc(t[0])] = { mac: mac, dev: t[2], reach: (index(line, 'REACHABLE') >= 0) };

				/* 链路本地地址只用来做 IP→MAC 匹配，不进设备列表 */
				if (substr(t[0], 0, 5) == 'fe80:')
					continue;

				let d = devmap[mac];
				if (!d)
					d = devmap[mac] = { ip4: null, ip6: [], iface: t[2], reach: 0 };
				push(d.ip6, t[0]);
				if (index(line, 'REACHABLE') >= 0)
					d.reach = 1;
			}
		}
		f6.close();
	}

	return map;
}

function accOf(mac) {
	let a = acc[mac];
	if (!a)
		a = acc[mac] = { up: 0, down: 0 };
	let d = today[mac];
	if (!d)
		d = today[mac] = { up: 0, down: 0 };
	return a;
}

/* 当天该设备的记录项，顺带补时长字段（终端详情页的历史图要） */
function devDayOf(mac) {
	let dd = devDaily[mac];
	if (!dd)
		dd = devDaily[mac] = {};

	const dk = dateStr(time());
	let dv = dd[dk];
	if (!dv)
		dv = dd[dk] = { up: 0, down: 0, active: 0, online: 0 };

	return dv;
}

function sessOf(mac) {
	let s = sess[mac];
	if (!s)
		s = sess[mac] = { start: time(), up: 0, down: 0, last: time(), active: 0, ev: null };
	return s;
}

function addTraffic(mac, up, down, cnt) {
	if (up == 0 && down == 0)
		return;

	const a = accOf(mac);
	a.up   += up;
	a.down += down;
	lastActive[mac] = time();

	const cs = sessOf(mac);
	cs.up   += up;
	cs.down += down;

	if (cnt) {
		const d = today[mac];
		d.up   += up;
		d.down += down;

		const h = hourNow();
		hourly[h].up   += up;
		hourly[h].down += down;

		/* 单机维度：今日分时 + 每日，终端详情页的两张图要用 */
		let dh = devHourly[mac];
		if (!dh)
			dh = devHourly[mac] = {};
		if (!dh[h])
			dh[h] = { up: 0, down: 0 };
		dh[h].up   += up;
		dh[h].down += down;

		const dv = devDayOf(mac);
		dv.up   += up;
		dv.down += down;
	}
}

/* ① conntrack 采样 */
function sampleCt() {
	const fd = open(CT_PATH, 'r');
	if (!fd)
		return false;

	let seen = {};
	let nCt = 0, nUp = 0, nDown = 0;
	const ts = time() * 1000;

	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		let t = tokens(line);
		if (length(t) < 8)
			continue;

		const proto = t[2];
		const srcs = [];

		for (let i = 0; i < length(t); i++)
			if (substr(t[i], 0, 4) == 'src=')
				push(srcs, i);

		if (!length(srcs))
			continue;

		const i1 = srcs[0];
		const i2 = (length(srcs) > 1) ? srcs[1] : -1;
		const end1 = (i2 < 0) ? length(t) : i2;

		const s1 = field(t, i1, end1, 'src');
		const d1 = field(t, i1, end1, 'dst');
		const sp1 = field(t, i1, end1, 'sport');
		const dp1 = field(t, i1, end1, 'dport');
		const b1 = int(field(t, i1, end1, 'bytes') ?? 0);
		const s2 = (i2 < 0) ? null : field(t, i2, length(t), 'src');
		const b2 = (i2 < 0) ? 0 : int(field(t, i2, length(t), 'bytes') ?? 0);

		if (!s1 || !d1)
			continue;

		let mac = ipmac[s1] ? ipmac[s1].mac : null;
		const localFirst = (mac != null);

		if (!mac && s2 && ipmac[s2])
			mac = ipmac[s2].mac;

		if (!mac)
			continue;

		/* 内网互访（NAS 拷文件之类）不经过 WAN，不计入上网流量 */
		if (isLanIp(s1) && isLanIp(d1))
			continue;

		const key = proto + '|' + s1 + ':' + (sp1 ?? '') + '|' + d1 + ':' + (dp1 ?? '');
		const prev = flowsCt[key];

		let du = 0, dd = 0;

		if (prev) {
			const d1b = (b1 >= prev.b1) ? b1 - prev.b1 : b1;
			const d2b = (b2 >= prev.b2) ? b2 - prev.b2 : b2;
			du = localFirst ? d1b : d2b;
			dd = localFirst ? d2b : d1b;
		}

		/* 方向比例：不管有没有增量，都用当前累计值算，供 HNAT 分摊 */
		const u = localFirst ? b1 : b2;
		const d = localFirst ? b2 : b1;
		nUp   += u;
		nDown += d;

		if (prev)
			addTraffic(mac, du, dd, true);

		seen[key] = { b1: b1, b2: b2, up: u, down: d, mac: mac };

		nCt++;
	}

	fd.close();

	/* 每轮重建：增量已经落进 acc，旧 key 不必保留 */
	flowsCt = seen;

	stat.ct = nCt;
	ctUp = nUp;
	ctDown = nDown;

	return { up: nUp, down: nDown };
}

/* 解析 all_entry 的一行 */
function parseHnat(line) {
	let r = {};
	const p = index(line, 'bytes=');
	if (p < 0)
		return null;

	let v = 0;
	for (let i = p + 6; i < length(line); i++) {
		const ch = substr(line, i, 1);
		if (ch < '0' || ch > '9')
			break;
		v = v * 10 + (+ch);
	}
	r.bytes = v;

	if (index(line, 'state=BIND') < 0)
		r.state = 'UNBIND';
	else
		r.state = 'BIND';

	const m = match(line, /SIP=([^()]+)\(sp=([0-9]+)\)->DIP=([^()]+)\(dp=([0-9]+)\)/);
	if (m == null)
		return null;

	r.sip = m[1]; r.sp = m[2]; r.dip = m[3]; r.dp = m[4];

	const mp = match(line, /prot=([0-9]+)/);
	r.prot = mp ? int(mp[1]) : 0;

	return r;
}

/* ② HNAT 采样
 *
 * all_entry 里每条连接有两条 BIND 记录：
 *   orig   SIP=192.168.2.216:49221 -> DIP=203.10.98.189:443    ← 只统计上行
 *   reply  SIP=203.10.98.189:443   -> DIP=192.168.1.230:49221  ← 只统计下行
 * 实测下载 10 MB：orig 只涨 ~211 KB（纯 ACK），reply 涨 11 MB。
 * 也就是说方向可以直接从条目类型判定，不需要按比例估算。
 * reply 的主机归属靠「交换 源/目的 四元组」反查 orig 得到，另有 NAT 后端口兜底。
 */
function sampleHw() {
	/* 监控和 TurboACC 的「HNAT 连接计数更新」互斥：
	 * 那个开关打开后驱动会把硬件计数回写 nf_conntrack，
	 * 此时 conntrack 已经含 offload 流量，再加一遍就重复了。 */
	if (updateNfct())
		return 0;

	const fd = open(HNAT_ENTRY, 'r');
	if (!fd)
		return 0;

	let rows = [];
	let origIdx = {};
	let portIdx = {};

	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		const h = parseHnat(line);
		if (h == null || h.state != 'BIND')
			continue;

		push(rows, h);

		if (ipmac[h.sip]) {
			const mac = ipmac[h.sip].mac;
			origIdx[h.sip + ':' + h.sp + '>' + h.dip + ':' + h.dp] = mac;
			portIdx[h.sp + '>' + h.dp] = mac;
		}
	}

	fd.close();

	let seen = {};
	let bind = length(rows), addUp = 0, addDown = 0, orphan = 0;

	for (let h in rows) {
		const key = h.sip + ':' + h.sp + '>' + h.dip + ':' + h.dp;
		let mac = null, isUp = true;

		if (ipmac[h.sip]) {
			mac = ipmac[h.sip].mac;
			isUp = true;
		}
		else {
			mac = origIdx[h.dip + ':' + h.dp + '>' + h.sip + ':' + h.sp];
			if (mac == null)
				mac = portIdx[h.dp + '>' + h.sp];
			isUp = false;
		}

		if (isLanIp(h.sip) && isLanIp(h.dip))
			continue;

		const prev = flowsHw[key];
		const delta = (prev == null) ? 0 : ((h.bytes >= prev.b) ? h.bytes - prev.b : h.bytes);

		seen[key] = { b: h.bytes };

		if (delta <= 0)
			continue;

		if (mac == null) {
			orphan++;
			continue;
		}

		if (isUp) {
			addTraffic(mac, delta, 0, true);
			addUp += delta;
		}
		else {
			addTraffic(mac, 0, delta, true);
			addDown += delta;
		}
	}

	flowsHw = seen;
	stat.hw = bind;
	stat.orphan = orphan;

	return addUp + addDown;
}

function readWan() {
	const I = '/sys/class/net/eth1/statistics/';
	let fd = open(I + 'rx_bytes', 'r');
	if (!fd)
		return;
	const rx = int(trim(fd.read('line')));
	fd.close();
	fd = open(I + 'tx_bytes', 'r');
	if (!fd)
		return;
	const tx = int(trim(fd.read('line')));
	fd.close();

	if (wan.prevRx && rx >= wan.prevRx) {
		wan.rateDown = int((rx - wan.prevRx) * 1000 / INTERVAL_MS);
		wan.rateUp   = int((tx - wan.prevTx) * 1000 / INTERVAL_MS);
	}
	wan.prevRx = rx;
	wan.prevTx = tx;
	wan.rx = rx;
	wan.tx = tx;
}

/* 记录上下线。devmap 由 readNeigh 维护，只含内网网段邻居。 */
function trackSessions() {
	const now = time();

	/* 上线：devmap 里出现、且这条会话还没记过事件 */
	for (let mac, d in devmap) {
		const cs = sessOf(mac);

		const step = max(1, min(INTERVAL_MS / 1000, now - (cs.lastTick ?? now)));
		const dv   = devDayOf(mac);

		/* ARP 可达、或最近 3 分钟有过流量，才算「真在线」。
		 * 拔电设备的残留条目不该继续累加在线时长。 */
		const idle0 = now - (lastActive[mac] ?? cs.start);
		if (d.reach || idle0 < OFFLINE_S)
			dv.online += step;

		if ((lastActive[mac] ?? 0) > (cs.lastTick ?? 0)) {
			cs.active += step;
			dv.active += step;
		}

		cs.lastTick = now;
		cs.last     = now;

		if (cs.ev == null) {
			const e = { ts: now, action: 0, mac: mac, up: 0, down: 0, dur: 0, active: 0 };
			push(events, e);
			if (length(events) > EV_MAX)
				shift(events);
			cs.ev = e;
		}
	}

	/* 离线：会话还在，但邻居表已经没有了；或者条目虽在、却已经 stale
	 * 并且很久没有任何流量（拔电的设备 ARP 条目会残留很久）。 */
	for (let mac, cs in sess) {
		const d     = devmap[mac];
		const idle  = now - (lastActive[mac] ?? cs.start);
		let   gone  = false;

		if (!d)
			gone = (idle >= OFFLINE_S);
		else if (!d.reach && idle >= OFFLINE_LONG)
			gone = true;

		if (!gone)
			continue;

		const dur = now - cs.start;

		/* 回填那条上线记录的最终值，避免离线后数字倒退成 0 */
		if (cs.ev) {
			cs.ev.up     = cs.up;
			cs.ev.down   = cs.down;
			cs.ev.dur    = dur;
			cs.ev.active = cs.active;
		}

		push(events, {
			ts: now, action: 1, mac: mac,
			up: cs.up, down: cs.down, dur: dur, active: cs.active
		});
		if (length(events) > EV_MAX)
			shift(events);

		delete sess[mac];
	}
}

/* 最新在前的记录列表；在线设备的上线记录用当前会话实时值 */
function buildRecords() {
	const now = time();
	let r = [];

	for (let i = length(events) - 1; i >= 0; i--) {
		const e = events[i];
		const cs = sess[e.mac];

		if (e.action == 0 && cs && cs.ev == e)
			push(r, {
				ts: e.ts, action: 0, mac: e.mac,
				up: cs.up, down: cs.down,
				dur: now - cs.start, active: cs.active
			});
		else
			push(r, {
				ts: e.ts, action: e.action, mac: e.mac,
				up: e.up, down: e.down,
				dur: e.dur, active: e.active
			});
	}

	return r;
}

function buildAndSave() {
	const now = time() * 1000;
	let snap = {};

	for (let m in acc)
		snap[m] = { up: acc[m].up, down: acc[m].down };

	push(samples, { ts: now, snap: snap });
	while (length(samples) > 2 && samples[0].ts < now - WINDOW_MS)
		shift(samples);

	/* 速率：窗口首尾差分 */
	let rates = {};
	if (length(samples) >= 2) {
		const f = samples[0], l = samples[length(samples) - 1];
		const span = l.ts - f.ts;
		if (span >= MIN_SPAN_MS) {
			for (let m in l.snap) {
				const p = f.snap[m];
				if (!p)
					continue;
				rates[m] = {
					upload:   max(0, int((l.snap[m].up - p.up) * 1000 / span)),
					download: max(0, int((l.snap[m].down - p.down) * 1000 / span))
				};
			}
		}
	}

	let totUp = 0, totDown = 0;
	let byMac = {};
	for (let m, r in rates) {
		byMac[m] = r;
		totUp   += r.upload;
		totDown += r.download;
	}

	let out = {
		ts: now,
		uptime: now - started * 1000,
		interval: INTERVAL_MS,
		hnat: {
			on: hnatOn(),
			bind: stat.hw,
			ct: stat.ct,
			orphan: stat.orphan,
			nfct: updateNfct(),
			err: stat.err
		},
		wan: { up: wan.rateUp, down: wan.rateDown, rx: wan.rx, tx: wan.tx },
		summary: { up: totUp, down: totDown, online: 0 },
		rates: {},
		traffic: {},
		today: {},
		hourly: hourly,
		hist: hist,
		online: {},
		dev: {},
		records: buildRecords(),
		devHourly: devHourly,
		devDaily: devDaily
	};

	let online = 0;
	for (let mac, d in devmap) {
		out.dev[mac] = {
			ip: d.ip4 ?? (length(d.ip6) ? d.ip6[0] : null),
			ip4: d.ip4,
			ip6: d.ip6,
			iface: d.iface,
			reach: d.reach
		};
		out.rates[mac] = byMac[mac] ?? { upload: 0, download: 0 };

		/* ARP / 邻居表里还有 MAC 就认为在线：条目本身由内核按 stale 超时回收，
		 * 比「必须有活跃流量」更贴近用户对在线设备的直觉 */
		out.online[mac] = 1;
		out.dev[mac].idle = time() - (lastActive[mac] ?? time());
		online++;
	}
	out.summary.online = online;

	/* acc 里可能有已经离线但还有累计值的设备，一并带出。
	 * 注意 acc 是「本次服务启动以来」的内存账，重启后为空；
	 * 今日累计可能来自 flash 账本，所以还要单独遍历 today 补一遍。 */
	for (let m in acc) {
		out.traffic[m] = { up: acc[m].up, down: acc[m].down };
		if (!out.rates[m])
			out.rates[m] = byMac[m] ?? { upload: 0, download: 0 };
	}

	for (let m, v in today) {
		out.today[m] = v;
		if (!out.traffic[m])
			out.traffic[m] = { up: 0, down: 0 };
		if (!out.rates[m])
			out.rates[m] = { upload: 0, download: 0 };
	}

	writefile(TMP, sprintf('%J', out));
	rename(TMP, OUT);
}

let tickNo = 0;

function tick() {
	/* 邻居表每 3 个周期刷新一次：IPv6 邻居变化很慢，
	 * 没必要每 2 秒 fork 一个 ip -6 neigh */
	if ((tickNo++ % 3) == 0)
		ipmac = readNeigh();

	rollDay();
	sampleCt();
	sampleHw();
	readWan();
	trackSessions();
	lastTs = time();
	buildAndSave();

	if ((time() - lastSave) >= SAVE_S) {
		saveHist();
		saveToday();
		lastSave = time();
	}

	if ((time() - lastState) >= STATE_S) {
		saveState();
		lastState = time();
	}
}

initLanPrefix();
initDay();
tick();

/* 账本不存在（首次装、刚刷机）就先落一次，避免下一轮重启又归零 */
if (!readJson(STATE_FILE)) {
	saveState();
	lastState = time();
}

uloop.init();
uloop.interval(INTERVAL_MS, tick);
uloop.run();
