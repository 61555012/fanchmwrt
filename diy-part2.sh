#!/bin/bash
#
# https://github.com/P3TERX/Actions-OpenWrt
# File name: diy-part2.sh
# Description: 自定义源码 / 插件（在 feeds update -a 之后、feeds install -a 之前执行）
#
# 为什么必须在这个时机:
#   - feeds update -a 之后: 否则 packages feed 会把 golang 目录重新拉回覆盖,
#     而且 feeds/fanchmwrt 这时才存在, overlay-feeds 无处可放
#   - feeds install -a 之前: 覆盖过的 feeds 内容才会被 install 采用
#
set -e

WORKSPACE="${GITHUB_WORKSPACE:-$(cd "$(dirname "$0")" && pwd)}"

echo "==== [diy-part2 1/6] 应用源码 overlay ===="
# overlay/ 是相对 openwrt 源码根的文件树:
#   package/fcm/                       fanchmwrt 核心包(fwxd / fwx / shortcut-fe / 主题)
#   package/base-files/files/bin/config_generate   默认 LAN 192.168.2.1 + 主机名 fanchmwrt
#   package/base-files/files/etc/uci-defaults/99-fwx-firewall-open   首启动放开防火墙
#   package/network/config/firewall4/  防火墙默认全放行(实际生效的是 firewall4/nftables)
#   target/linux/generic/hack-6.12/    fwx / shortcut-fe 的内核结构体钩子补丁
if [ ! -d "$WORKSPACE/overlay" ]; then
	echo "    [错误] 找不到 $WORKSPACE/overlay"
	exit 1
fi
cp -rf "$WORKSPACE/overlay/." .
chmod +x package/base-files/files/bin/config_generate
chmod +x package/base-files/files/etc/uci-defaults/99-fwx-firewall-open
echo "    overlay 已应用: $(find package/fcm -maxdepth 1 -mindepth 1 -type d | wc -l) 个 fcm 子包"

echo "==== [diy-part2 2/6] 应用 fanchmwrt LuCI 前端 overlay ===="
# 覆盖 feeds/fanchmwrt 里被改过的文件:
#   - 在线用户 / 仪表盘按 MAC OUI 显示品牌 logo(首帧即最终形态, 不闪)
#   - 网络设置隐藏"网络加速"菜单
#   - 主题样式修正
if [ -d feeds/fanchmwrt ]; then
	cp -rf "$WORKSPACE/overlay-feeds/." feeds/fanchmwrt/
	echo "    feeds/fanchmwrt 已覆盖"
else
	echo "    [错误] feeds/fanchmwrt 不存在, 请检查 diy-part1.sh 里的 src-git 行"
	exit 1
fi

echo "==== [diy-part2 3/6] 替换 golang feed 为 sbwml 26.x ===="
rm -rf feeds/packages/lang/golang
git clone --depth=1 https://github.com/sbwml/packages_lang_golang -b 26.x feeds/packages/lang/golang

echo "==== [diy-part2 4/6] 重拉 mosdns 与 v2ray-geodata ===="
find ./ | grep Makefile | grep v2ray-geodata | xargs -r rm -f
find ./ | grep Makefile | grep mosdns | xargs -r rm -f
git clone --depth=1 https://github.com/sbwml/luci-app-mosdns -b v5 package/mosdns
git clone --depth=1 https://github.com/sbwml/v2ray-geodata package/v2ray-geodata

echo "==== [diy-part2 5/6] 修复 S20P 两个 2.5G 口指示灯 (0x001b -> 0x321b) ===="
LED_DTS="target/linux/mediatek/dts-ext/mt7986a-clx-s20p.dts"
if [ -f "$LED_DTS" ]; then
  sed -i 's/realtek,led-act-select = <0x001b>/realtek,led-act-select = <0x321b>/g' "$LED_DTS"
  if grep -q 'realtek,led-act-select = <0x321b>' "$LED_DTS"; then
    echo "    DTS LED 配置已应用: modeA + 400ms/12.5%/60ms + 10M LPI"
  else
    echo "    [警告] 未匹配到 0x001b, 请确认是否已修复或路径变化"
  fi
else
  echo "    [警告] 未找到 $LED_DTS, 跳过 LED 修复"
fi

# 内核 6.12 的 733 补丁只定义了 rtl8221b_config_led() 却从未调用它(死代码),
# 导致 realtek,led-act-select 等属性完全不生效、2.5G 灯不亮。
# 6.6 的 790 补丁是在 rtl822xb_config_init 末尾调用, 此处把调用补回去。
LED_PATCH="target/linux/mediatek/patches-6.12/734-net-phy-realtek-call-rtl8221b_config_led.patch"
if [ -d target/linux/mediatek/patches-6.12 ]; then
cat > "$LED_PATCH" <<'EOF'
From: S20P build fix
Subject: net: phy: realtek: call rtl8221b_config_led from rtl822xb_config_init

The 6.12 backport (patch 733) defines rtl8221b_config_led() but never
calls it, so the realtek,led-*-select DT properties have no effect and
the 2.5G port LEDs stay dark (e.g. CLX S20P). Restore the call that
exists in the 6.6 patch (790).
---
--- a/drivers/net/phy/realtek/realtek_main.c
+++ b/drivers/net/phy/realtek/realtek_main.c
@@ -1520,6 +1520,12 @@
 static int rtl822xb_config_init(struct phy_device *phydev)
 {
-	return rtl822x_set_serdes_option_mode(phydev, false);
+	int ret;
+
+	ret = rtl822x_set_serdes_option_mode(phydev, false);
+	if (ret < 0)
+		return ret;
+
+	return rtl8221b_config_led(phydev);
 }
 
 static int rtl822xb_read_status(struct phy_device *phydev)
EOF
  echo "    已生成补丁: $LED_PATCH"
else
  echo "    [警告] 未找到 patches-6.12 目录, 跳过"
fi

echo "==== [diy-part2 6/6] 完成, 关键定制项自检 ===="
grep -q '192.168.2.1' package/base-files/files/bin/config_generate && echo "    默认 LAN: 192.168.2.1"
grep -q "hostname='fanchmwrt'" package/base-files/files/bin/config_generate && echo "    主机名  : fanchmwrt"
grep -q 'ACCEPT' package/network/config/firewall4/files/etc/config/firewall && echo "    防火墙  : input/output/forward 全放行"
ls target/linux/generic/hack-6.12/950-*.patch target/linux/generic/hack-6.12/951-*.patch >/dev/null 2>&1 && echo "    fwx 内核钩子补丁: 已就位"
ls feeds/fanchmwrt/luci-app-fwx-resources/htdocs/luci-static/resources/oui/oui-vendors.js >/dev/null 2>&1 && echo "    设备品牌 logo 数据: 已就位"
