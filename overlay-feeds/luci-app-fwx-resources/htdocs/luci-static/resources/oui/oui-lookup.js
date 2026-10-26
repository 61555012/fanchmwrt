/* SPDX-License-Identifier: GPL-2.0-only
 *
 * fanchmwrt 在线用户品牌识别
 * 按 MAC OUI 查厂商，并在用户头像位置显示对应品牌 logo。
 *
 * 数据与品牌图标来自 coolsnowwolf/luci 的 luci-app-oui，
 * 许可信息见同目录 LICENSE.md / LICENSE.macdb / DISCLAIMER.md。
 *
 * 用法（推荐，同步一次成型、图标不闪）：
 *   在 oui-lookup.js 之前用普通 <script> 引入 oui-vendors.js，
 *   拼 HTML 时调用 FwxOUI.imgHtml(mac)，有品牌则返回 <img> 片段，
 *   无品牌（或随机 MAC）返回 null，由页面回退到首字母头像。
 *
 * 用法（兼容旧写法，会二次替换 DOM）：
 *   给元素加 data-oui-mac="MAC 地址"，脚本会监听 DOM 变化补全图标。
 */
(function (window, document) {
	'use strict';

	if (window.FwxOUI)
		return;

	var DB_FILE = 'vendors-d337209f8c00.json';
	var OUI_DIR = (function () {
		var s = document.currentScript;
		if (s && s.src)
			return s.src.replace(/[^\/]*$/, '');
		return '/luci-static/resources/oui/';
	})();

	/* oui-vendors.js 同步注入时可以立刻查表；缺失则回退到异步 XHR */
	var database = (function () {
		var db = window.FwxOUI_DB;
		if (db && Array.isArray(db.vendors) && db.prefixes)
			return db;
		return null;
	})();

	var pendingLoad = null;
	var observer = null;
	var hydrateTimer = null;

	/* ---------- MAC 处理 ---------- */

	function normalize(mac, allowLocal) {
		if (typeof mac !== 'string')
			return null;
		mac = mac.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
		if (mac.length !== 12 || /[^0-9A-F]/.test(mac))
			return null;
		var flags = parseInt(mac.slice(0, 2), 16);
		/* 组播地址没有可靠 OUI；本地管理地址（随机 MAC）按需放行 */
		if (flags & 1)
			return null;
		if (!allowLocal && (flags & 2))
			return null;
		return mac;
	}

	function isLocalMac(mac) {
		var hex = normalize(mac, true);
		return hex ? !!(parseInt(hex.slice(0, 2), 16) & 2) : false;
	}

	function escapeAttr(value) {
		return String(value == null ? '' : value)
			.replace(/&/g, '&amp;')
			.replace(/"/g, '&quot;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;');
	}

	/* ---------- 数据库加载（仅兜底） ---------- */

	function load() {
		if (database)
			return Promise.resolve(database);

		if (pendingLoad)
			return pendingLoad;

		pendingLoad = new Promise(function (resolve) {
			try {
				var xhr = new XMLHttpRequest();
				xhr.open('GET', OUI_DIR + DB_FILE, true);
				xhr.timeout = 8000;
				xhr.onload = function () {
					try {
						if (xhr.status === 200) {
							var data = JSON.parse(xhr.responseText);
							if (data && Array.isArray(data.vendors) && data.prefixes)
								database = data;
						}
					} catch (e) { /* 数据异常时保持首字母头像 */ }
					resolve(database);
				};
				xhr.onerror = xhr.ontimeout = xhr.onabort = function () { resolve(null); };
				xhr.send();
			} catch (e) {
				resolve(null);
			}
		});

		return pendingLoad;
	}

	function lookup(mac) {
		var hex = normalize(mac);
		if (!hex || !database)
			return null;

		var lengths = [9, 7, 6];
		for (var i = 0; i < lengths.length; i++) {
			var key = hex.slice(0, lengths[i]);
			if (Object.prototype.hasOwnProperty.call(database.prefixes, key)) {
				var idx = database.prefixes[key];
				if (idx === null || idx === undefined)
					return null;
				var vendor = database.vendors[idx];
				if (vendor && /^[a-z0-9]+$/.test(vendor[0]))
					return { id: vendor[0], name: vendor[1] };
				return null;
			}
		}
		return null;
	}

	/* ---------- 同步渲染接口 ---------- */

	/* 返回 { id, name, url }，无品牌返回 null */
	function logo(mac) {
		var vendor = lookup(mac);
		if (!vendor)
			return null;
		return {
			id: vendor.id,
			name: vendor.name,
			url: OUI_DIR + vendor.id + '.svg'
		};
	}

	/* 返回可直接拼进 innerHTML 的 <img> 片段，无品牌返回 null */
	function imgHtml(mac) {
		var info = logo(mac);
		if (!info)
			return null;
		return '<img class="fwx-oui-logo" src="' + escapeAttr(info.url) +
			'" alt="" title="' + escapeAttr(info.name) + '" draggable="false">';
	}

	/* ---------- 图标补全（旧写法兼容） ---------- */

	function hydrateNode(node) {
		if (!node || node.nodeType !== 1)
			return;

		var mac = node.getAttribute('data-oui-mac');
		if (!mac || node.getAttribute('data-oui-done') === '1')
			return;

		node.setAttribute('data-oui-done', '1');

		if (!database) {
			/* 数据未就绪：等加载完成后再跑一轮 */
			load().then(scheduleHydrate);
			return;
		}

		var vendor = lookup(mac);
		if (!vendor)
			return;

		var original = node.textContent;
		var img = document.createElement('img');
		img.className = 'fwx-oui-logo';
		img.alt = '';
		img.title = vendor.name;
		img.onerror = function () {
			node.classList.remove('fwx-oui-logo-wrap');
			while (node.firstChild)
				node.removeChild(node.firstChild);
			node.textContent = original;
		};
		img.src = OUI_DIR + vendor.id + '.svg';

		while (node.firstChild)
			node.removeChild(node.firstChild);
		node.appendChild(img);
		node.classList.add('fwx-oui-logo-wrap');
	}

	function hydrate(root) {
		root = root || document;
		if (!root.querySelectorAll)
			return;

		var nodes = root.querySelectorAll('[data-oui-mac]');
		for (var i = 0; i < nodes.length; i++)
			hydrateNode(nodes[i]);
	}

	function scheduleHydrate() {
		if (hydrateTimer)
			return;
		hydrateTimer = window.setTimeout(function () {
			hydrateTimer = null;
			hydrate(document);
		}, 120);
	}

	/* ---------- 初始化 ---------- */

	function start() {
		load().then(function () {
			hydrate(document);
		});

		if (observer || !document.body)
			return;

		observer = new MutationObserver(scheduleHydrate);
		observer.observe(document.body, { childList: true, subtree: true });
	}

	window.FwxOUI = {
		lookup: lookup,
		logo: logo,
		imgHtml: imgHtml,
		isLocalMac: isLocalMac,
		normalize: normalize,
		hydrate: hydrate,
		start: start,
		dir: OUI_DIR,
		ready: function () { return !!database; },

		/* 旧接口：把 MAC 规范化后塞进 data-oui-mac */
		normalizedMac: function (mac) {
			var hex = normalize(mac, true);
			return hex ? hex.match(/.{2}/g).join(':') : null;
		},

		macAttr: function (mac) {
			var value = window.FwxOUI.normalizedMac(mac);
			return value ? ' data-oui-mac="' + value + '"' : '';
		}
	};

	if (document.readyState === 'loading')
		document.addEventListener('DOMContentLoaded', start);
	else
		start();
})(window, document);
