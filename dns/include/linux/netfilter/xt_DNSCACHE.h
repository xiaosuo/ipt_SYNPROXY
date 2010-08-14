#ifndef _XT_DNSCACHE_H
#define _XT_DNSCACHE_H

#include <linux/types.h>

enum {
	XT_DNSCACHE_ACTION_CACHE,
	XT_DNSCACHE_ACTION_QUERY,
	__XT_DNSCACHE_ACTION_MAX,
};

#define XT_DNSCACHE_ACTION_MAX (__XT_DNSCACHE_ACTION_MAX - 1)

struct xt_dnscache_info {
	__u32	action;
};

#endif /* _XT_DNSCACHE_H */
