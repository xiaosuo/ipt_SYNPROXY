/* (C) 2010- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/dns.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("DNS library");

int qn_valid(u8 *header, unsigned int len, u8 *qn)
{
	int label_len, recursion, retval;
	u8 *end = header + len;

	retval = 0;
	recursion = 0;
	for (;;) {
		if (qn >= end)
			goto err;
		label_len = *qn++;
		if (!recursion)
			++retval;
		if (label_len == 0)
			break;
		if (label_len > 63) {
			if ((label_len & 0xc0) != 0xc0 || qn >= end)
				goto err;
			qn = header + ((label_len & (~0xc0)) << 8) + *qn;
			if (!recursion)
				++retval;
			if (++recursion > 255)
				goto err;
		} else {
			if (qn + label_len > end)
				goto err;
			if (!qn_label_valid(qn, label_len))
				goto err;
			qn += label_len;
			if (!recursion)
				retval += label_len;
		}
	}

out:
	return retval;

err:
	retval = -EINVAL;
	goto out;
}
EXPORT_SYMBOL(qn_valid);

static inline u8 *qn_label(u8 *q, u8 *h)
{
	int label_len;

	for (;;) {
		label_len = *q;
		if (label_len <= 63)
			break;
		q = h + ((label_len & (~0xc0)) << 8) + q[1];
	}

	return q;
}

int qn_travel(u8 *q, u8 *h,
	      int (*func)(void *data, u8 *label, unsigned int label_len),
	      void *data)
{
	int label_len;
	int retval;

	for (;;) {
		q = qn_label(q, h);
		label_len = *q++;
		retval = func(data, q, label_len);
		if (label_len == 0 || retval)
			break;
		q += label_len;
	}

	return retval;
}
EXPORT_SYMBOL(qn_travel);

static int __qn_printk(void *data, u8 *label, unsigned int label_len)
{
	bool *ppoint = data;

	if (label_len == 0)
		return 0;
	if (*ppoint)
		printk(".");
	else
		*ppoint = true;
	printk("%.*s", label_len, label);

	return 0;
}

void qn_printk(u8 *q, u8 *h)
{
	bool point = false;

	qn_travel(q, h, __qn_printk, &point);
}
EXPORT_SYMBOL(qn_printk);

int qn_cmp(u8 *q1, u8 *q2, u8 *h1, u8 *h2)
{
	int len1, len2;

	for (;;) {
		q1 = qn_label(q1, h1);
		q2 = qn_label(q2, h2);
		len1 = *q1;
		len2 = *q2;
		if (len1 != len2)
			return len1 - len2;
		if (len1 == 0)
			break;
		len1 = strncasecmp(++q1, ++q2, len1);
		if (len1 != 0)
			return len1;
		q1 += len2;
		q2 += len2;
	}

	return 0;
}
EXPORT_SYMBOL(qn_cmp);

const char *dns_type_str(u16 type)
{
#define DNS_TYPE_STR(x)	[DNS_TYPE(x)] = #x
	static const char *type_str[] = {
		DNS_TYPE_STR(A),
		DNS_TYPE_STR(NS),
		DNS_TYPE_STR(CNAME),
		DNS_TYPE_STR(PTR),
		DNS_TYPE_STR(HINFO),
		DNS_TYPE_STR(MX),
	};

	if (type >= ARRAY_SIZE(type_str))
		return NULL;
	return type_str[type];
}
EXPORT_SYMBOL(dns_type_str);
