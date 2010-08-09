#ifndef _XT_DNS_H
#define _XT_DNS_H

#include <linux/types.h>

struct xt_dns_info {
	__u32	invert;
	__u8	fqdn[512];
};

#endif /* _XT_DNS_H */
