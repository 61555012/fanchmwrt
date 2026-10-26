#!/bin/bash
#
# https://github.com/P3TERX/Actions-OpenWrt
# File name: diy-part1.sh
# Description: 自定义 feeds（在 feeds update -a 之前执行）
#
set -e

# ---------------------------------------------------------------------------
# fanchmwrt 套件（LuCI 前端）
#   核心包 fwxd / fwx / shortcut-fe / luci-theme-fanchmwrt 由 overlay/ 提供，
#   这个 feed 只负责 luci-app-fwx-* 一整套界面。
# ---------------------------------------------------------------------------
if ! grep -q '^src-git fanchmwrt ' feeds.conf.default; then
	echo 'src-git fanchmwrt https://github.com/fanchmwrt/fanchmwrt-packages.git;main' >>feeds.conf.default
	echo "已追加 fanchmwrt feed"
else
	echo "fanchmwrt feed 已存在"
fi

echo "==== [diy-part1] 当前 feeds.conf.default ===="
cat feeds.conf.default
