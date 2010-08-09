
#include <linux/module.h>

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
			if (++recursion > 3)
				goto err;
		} else {
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
		len1 = memcmp(++q1, ++q2, len1);
		if (len1 != 0)
			return len1;
		q1 += len2;
		q2 += len2;
	}

	return 0;
}
EXPORT_SYMBOL(qn_cmp);
