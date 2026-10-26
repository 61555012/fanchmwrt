// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>
 */
#ifndef __FWX_OFFLOAD_ACCT_H__
#define __FWX_OFFLOAD_ACCT_H__

/* 初始化硬件加速流量统计（挂载 debugfs、探测 PPE 转发表） */
void fwx_offload_acct_init(void);

/* 周期采样，内部按 2 秒限频，由主循环每秒调用一次即可 */
void fwx_offload_acct_poll(void);

#endif
