#ifndef _DNS_H
#define _DNS_H

#include <linux/types.h>

struct dnshdr {
	__be16	id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__be16	rd	: 1,
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
	__be16	qr	: 1,
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
	__be16	nr_q;
	__be16	nr_r;
	__be16	nr_a;
	__be16	nr_er;
};

#endif /* _DNS_H */
