#ifndef _XT_DNS_H
#define _XT_DNS_H

#include <linux/types.h>

struct xt_dns_info {
	__u32	invert;
	char	fqdn[1024];
};

#endif /* _XT_DNS_H */
