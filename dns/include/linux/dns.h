#ifndef _DNS_H
#define _DNS_H

#include <linux/types.h>

struct dnshdr {
	__be16	id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rd	: 1,
		tc	: 1,
		aa	: 1,
		opcode	: 4,
		qr	: 1,
		rcode	: 4,
		cd	: 1,
		ad	: 1,
		unused	: 1,
		ra	: 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	qr	: 1,
		opcode	: 4,
		aa	: 1,
		tc	: 1,
		rd	: 1,
		ra	: 1,
		unused	: 1,
		ad	: 1,
		cd	: 1,
		rcode	: 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	__be16	qdcount;
	__be16	ancount;
	__be16	nscount;
	__be16	arcount;
};

#define DNS_CLASS_IN	1
#define DNS_TYPE(x)	DNS_TYPE_##x

enum {
	DNS_TYPE(A)	= 1,
	DNS_TYPE(NS)	= 2,
	DNS_TYPE(CNAME)	= 5,
	DNS_TYPE(PTR)	= 12,
	DNS_TYPE(HINFO)	= 13,
	DNS_TYPE(MX)	= 15,
};

struct dns_q_fixed {
	__be16	type;
	__be16	class;
} __packed;

struct dns_rr_fixed {
	__be16	type;
	__be16	class;
	__be32	ttl;
	__be16	len;
} __packed;

#ifdef __KERNEL__
int qn_valid(u8 *header, unsigned int len, u8 *qn);
int qn_cmp(u8 *q1, u8 *q2, u8 *h1, u8 *h2);
int qn_travel(u8 *q, u8 *h,
	      int (*func)(void *data, u8 *label, unsigned int label_len),
	      void *data);
void qn_printk(u8 *q, u8 *h);
const char *dns_type_str(u16 type);
#endif

#endif /* _DNS_H */
