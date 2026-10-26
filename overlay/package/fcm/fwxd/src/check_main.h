// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __CHECK_MAIN_H__
#define __CHECK_MAIN_H__

#define DEFAULT_INTERNET_CHECK_DOMAIN "www.bing.com"
#define DEFAULT_INTERNET_CHECK_INTERVAL 5

int fwx_valid_internet_check_domain(const char *domain);
int fwx_parse_internet_check_interval(const char *value);
int fwx_get_internet_check_interval(void);
void fwx_note_api_activity(void);
int fwx_get_internet_check_status(void);

int start_check_thread(void);


void stop_check_thread(void);

#endif 

