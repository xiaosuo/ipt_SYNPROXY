#ifndef __SLIST_H

/* singly-linked list */

struct slist_head {
	struct slist_head *next;
};

#define slist_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define SLIST_HEAD_INIT { .next = NULL }
#define SLIST_HEAD(name) struct slist_head name = SLIST_HEAD_INIT

static inline void INIT_SLIST_HEAD(struct slist_head *h)
{
	h->next = NULL;
}

static inline bool slist_empty(struct slist_head *h)
{
	return h->next == NULL;
}

#define slist_first_entry(h, type, member) \
	((h)->next ? slist_entry((h)->next, type, member) : NULL)

static inline void slist_push(struct slist_head *n, struct slist_head *h)
{
	n->next = h->next;
	h->next = n;
}

static inline struct slist_head *slist_pop(struct slist_head *h)
{
	struct slist_head *n;

	n = h->next;
	if (n)
		h->next = n->next;

	return n;
}

static inline struct slist_head *slist_pop_init(struct slist_head *h)
{
	struct slist_head *n = slist_pop(h);

	if (n)
		INIT_SLIST_HEAD(n);

	return n;
}

static inline void __slist_splice(struct slist_head *first,
				  struct slist_head *to)
{
	struct slist_head **ptail;

	for (ptail = &to->next; *ptail; ptail = &(*ptail)->next)
		;
	*ptail = first;
}

static inline void slist_splice_init(struct slist_head *from,
				     struct slist_head *to)
{
	if (from->next != NULL) {
		__slist_splice(from->next, to);
		INIT_SLIST_HEAD(from);
	}
}

#define slist_for_each(pos, head) \
	for (pos = (head)->next; pos && ({ prefetch(pos->next); 1; }); \
	     pos = pos->next)

#define slist_for_each_entry(tpos, pos, head, member) \
	for (pos = (head)->next; \
	     pos && ({ prefetch(pos->next); 1; }) && \
		 ({ tpos = slist_entry(pos, typeof(*tpos), member); 1; }); \
	     pos = pos->next)

#define slist_del(pos, n, ppos) \
	do { \
		*ppos = pos->next; \
		n = container_of(ppos, struct slist_head, next); \
	} while (0)

#define slist_add_before(new, pos, ppos) \
	do { \
		(new)->next = pos; \
		*ppos = (new); \
	} while (0)

#define slist_add_after(new, pos, n) \
	do { \
		(new)->next = pos->next; \
		pos->next = (new); \
		n = (new); \
	} while (0)

#define slist_for_each_safe(pos, n, ppos, head) \
	for (ppos = &(head)->next; (n = pos = *ppos); ppos = &n->next)

#define slist_for_each_entry_safe(tpos, pos, n, ppos, head, member) \
	for (ppos = &(head)->next; \
	     (n = pos = *ppos) && \
		  ({ tpos = slist_entry(pos, typeof(*tpos), member); 1; }); \
	     ppos = &n->next)

/* singly-linked tail list */

struct tlist_head {
	struct slist_head *next;
	struct slist_head **ptail;
};

#define TLIST_HEAD_INIT(name) { .next = NULL, .ptail = &(name).next }
#define TLIST_HEAD(name) struct tlist_head name = TLIST_HEAD_INIT(name)

static inline void INIT_TLIST_HEAD(struct tlist_head *h)
{
	h->next = NULL;
	h->ptail = &h->next;
}

static inline bool tlist_empty(struct tlist_head *h)
{
	return h->next == NULL;
}

#define tlist_first_entry slist_first_entry

#define tlist_last_entry(h, type, member) \
	((h)->next ? \
	 slist_entry((struct slist_head*)((h)->ptail), type, member) : NULL)

static inline void tlist_append(struct slist_head *n, struct tlist_head *h)
{
	*(h->ptail) = n;
	h->ptail = &n->next;
}

static inline void tlist_push(struct slist_head *n, struct tlist_head *h)
{
	n->next = h->next;
	h->next = n;
	if (h->ptail == &h->next)
		h->ptail = &n->next;
}

static inline struct slist_head *tlist_pop(struct tlist_head *h)
{
	struct slist_head *n = h->next;

	if (n) {
		h->next = n->next;
		if (n->next == NULL)
			h->ptail = &h->next;
	}

	return n;
}

static inline struct slist_head *tlist_pop_init(struct tlist_head *h)
{
	struct slist_head *n = tlist_pop(h);

	if (n)
		INIT_SLIST_HEAD(n);

	return n;
}

static inline void tlist_splice_init(struct tlist_head *from,
				     struct tlist_head *to)
{
	if (!tlist_empty(from)) {
		*(to->ptail) = from->next;
		to->ptail = from->ptail;
		INIT_TLIST_HEAD(from);
	}
}

static inline void tlist_splice_to_slist_init(struct tlist_head *from,
					      struct slist_head *to)
{
	if (!tlist_empty(from)) {
		__slist_splice(from->next, to);
		INIT_TLIST_HEAD(from);
	}
}

#define tlist_for_each slist_for_each

#define tlist_for_each_entry slist_for_each_entry

#define tlist_del(pos, n, ppos, head) \
	do { \
		slist_del(pos, n, ppos); \
		if (pos->next == NULL) \
			(head)->ptail = ppos; \
	} while (0)

#define tlist_add_before slist_add_before

#define tlist_add_after(new, pos, n, head) \
	do { \
		slist_add_after(new, pos, n); \
		if ((new)->next == NULL) \
			(head)->ptail = &(new)->next; \
	} while (0)

#define tlist_for_each_safe slist_for_each_safe

#define tlist_for_each_entry_safe slist_for_each_entry_safe

#endif /* __SLIST_H */
