// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _FWX_FASTPATH_H_
#define _FWX_FASTPATH_H_

#include <linux/types.h>
#include <linux/if_ether.h>

struct net_device;

struct fwx_fastpath_packet {
	u8 src_mac[ETH_ALEN];
	u8 dest_mac[ETH_ALEN];
	u32 bytes;
	bool is_v6;
};

/* Statistics only; the caller retains ownership of all arguments. */
void fwx_account_fastpath_packet(struct net_device *in,
				 const struct fwx_fastpath_packet *packet);

#endif
