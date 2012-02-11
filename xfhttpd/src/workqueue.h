
#ifndef __WORKQUEUE_H
#define __WORKQUEUE_H

#include "list.h"

enum work_state {
	WORK_STATE_PENDING,
	WORK_STATE_RUNNING,
};

struct work {
	struct list_head	list;
	void			(*func)(void*);
	void			*arg;
	enum work_state		state;
};

#endif /* __WORKQUEUE_H */
