# S20P 固件云编译（chasey-dev 25.12 + fanchmwrt）

基于 [chasey-dev/immortalwrt-mt798x-rebase](https://github.com/chasey-dev/immortalwrt-mt798x-rebase) 的 `25.12` 分支，
为 **CLX S20P（mt7986a / mediatek-filogic）** 定制，用 GitHub Actions 自动编译。

## 机型与基础

| 项目 | 内容 |
|------|------|
| 目标平台 | `mediatek` / `filogic` |
| 设备 | `clx_s20p`（CLX S20P，MT7986A，AX6000） |
| 内核 | 6.12 |
| 默认管理地址 | `http://192.168.2.1` |
| 主机名 | `fanchmwrt` |
| 默认主题 | fanchmwrt（**不编译 argon**），默认**浅色**，可切深色 |

## 固件特性

- **fanchmwrt 套件**
  - 核心：`fwxd`、`fwx`（kmod-fwx）、`shortcut-fe`（kmod-shortcut-fe）、`libfwx_common`
  - 界面：`luci-app-fwx-*` 全套（在线用户、仪表盘、网络设置、无线、应用过滤、
    网址过滤、MAC 过滤/黑名单、流量统计、会话统计、特征库、系统设置）
  - 主题：`luci-theme-fanchmwrt`，附中文语言包
  - **不编译应用中心**（`luci-app-fwx-app-center` 显式关闭）
- **MTK 闭源 WiFi**：`kmod-mt_wifi`(7.6.7.3) + `kmod-conninfra` + `kmod-warp` + `wifi-dats`
  + `luci-app-mtwifi-cfg`，**不使用 mt76**
- **MTK 硬件加速**：`kmod-mediatek_hnat`（PPE 硬件 NAT 卸载）+ `luci-app-turboacc-mtk` + BBR
  - fwxd 已加入 PPE 硬件转发流量统计（读 `/sys/kernel/debug/ppe*/entries`），
    硬件加速下的流量也能进流量统计
- **硬件加速下的逐设备流量统计（client-rates）**
  - 采样器常驻：conntrack + `/sys/kernel/debug/hnat/all_entry` 双源采样，每 2 秒一次
  - fwx 的仪表盘 / 终端列表 / 终端记录 / 流量统计四个页面都改吃采样器数据，
    开硬件加速后不再是「有线能统计、WiFi 恒为 0」
  - 今日账本落 `/etc/client-rates/state.json`，服务重启不清零
  - 开关「HNAT 连接计数更新」必须保持关闭（否则重复计数、高估约 3 倍），
    `files/etc/uci-defaults/98-client-rates` 会兜底关掉
- **应用图标**：562 个 app_icons 保留在 `/luci-static/resources/app_icons/`，
  供 fwx 应用过滤 / 在线用户展示（路径必须与模板里的 `<%=resource%>/app_icons/` 一致）
- **设备品牌识别**：在线用户 / 仪表盘按 MAC OUI 显示 42 个品牌 logo（8712 条前缀），
  同步查表、首帧即最终形态，轮询刷新不闪烁
- **防火墙默认全放行**：firewall4 的 `input` / `output` / `forward` 默认 `ACCEPT`
  （首启动 `99-fwx-firewall-open` 兜底，兼容保留配置升级）
- **mosdns**：sbwml 26.x golang feed + `luci-app-mosdns` v5 + `v2ray-geodata`
- **2.5G 口 LED 修复**：DTS `0x001b → 0x321b`，并补回内核 6.12 丢失的
  `rtl8221b_config_led()` 调用

### 已移除

- **argon 主题**（`luci-theme-argon` / `luci-app-argon-config`）：改用 fanchmwrt 主题
- **OpenAppFilter / OAF**（`luci-app-oaf` / `OpenAppFilter`）：
  改用 fanchmwrt 的 `luci-app-fwx-appfilter`。
  **只移除程序本体**，562 个应用图标保留下来给 fwx 应用过滤用
  （`files/www/luci-static/resources/app_icons/`）

## 仓库结构

```
.config                     编译配置（包选择）
diy-part1.sh                feeds update 前：追加 fanchmwrt feed
diy-part2.sh                feeds update 后 / install 前：
                            - 应用 overlay/ 与 overlay-feeds/
                            - golang 26.x feed、mosdns、v2ray-geodata
                            - 2.5G 口 LED 修复
overlay/                    直接覆盖到源码树根的文件
  package/fcm/              fanchmwrt 核心包（含 fwxd 的 PPE 流量统计）
  package/base-files/       默认 IP 192.168.2.1 + 主机名 fanchmwrt
  package/network/config/firewall4/   防火墙默认全放行
  target/linux/generic/hack-6.12/     fwx / shortcut-fe 内核钩子补丁
overlay-feeds/              覆盖到 feeds/fanchmwrt 的文件
  luci-app-fwx-*/           品牌 logo、菜单调整、主题排版修正
files/                      直接拷入 openwrt/files（固件根目录）
  etc/config/upnpd          UPnP 默认配置
  etc/fwxd/feature.bin      fwx 特征库
  etc/shadow                默认 root 密码
  etc/init.d/                client-rates（流量采样器）、hnat-l2br（开机补写 l2br_toggle）
  etc/uci-defaults/98-client-rates   启用上面两个服务、关掉 nfct 回写
  usr/share/client-rates/   sampler.uc（conntrack + HNAT all_entry 双源采样）
  usr/lib/lua/luci/crstat.lua         fwx 控制器读采样器的中间层
  usr/lib/lua/luci/controller/        fwx_dashboard / fwx_traffic_stat / user / fwx_user_record 改造版
  usr/lib/lua/luci/view/fwx_user_record/user_record.htm   终端记录页改造版
  usr/share/rpcd/           ucode 只读接口 + ACL
  www/luci-static/resources/app_icons/   562 个应用图标（路径须与 <%=resource%>/app_icons/ 对齐）
.github/workflows/s20p-builder.yml   编译流程
```

## 怎么编译

1. 打开仓库 **Actions** → 左侧 **S20P-ChaseyDev-25.12** → 右上 **Run workflow**
2. 勾选 `ssh` 可以开 tmate 调试（可选）
3. 约 1.5～2 小时（首次要编工具链；之后命中 `toolchain-cache` 会快很多）
4. 完成后到 **Releases** 下载 `*sysupgrade.bin`

也可以在网页上用 `repository_dispatch` 触发，或等每天 06:00（北京时间）的定时编译。

## 刷机

```
sysupgrade -n /tmp/immortalwrt-mediatek-filogic-clx_s20p-squashfs-sysupgrade.bin
```

或者 LuCI → 系统 → 备份/升级 → 刷写固件（不勾选"保留配置"更干净）。
刷完访问 `http://192.168.2.1`，首次登录 root 密码为空（除非 `files/etc/shadow` 覆盖了密码）。

## 致谢

- [P3TERX/Actions-OpenWrt](https://github.com/P3TERX/Actions-OpenWrt) 模板
- [chasey-dev/immortalwrt-mt798x-rebase](https://github.com/chasey-dev/immortalwrt-mt798x-rebase)
- [fanchmwrt](https://github.com/fanchmwrt) 套件
- [sbwml](https://github.com/sbwml) golang / mosdns / v2ray-geodata
- [coolsnowwolf/luci](https://github.com/coolsnowwolf/luci) 的 luci-app-oui（品牌 logo 数据来源）
