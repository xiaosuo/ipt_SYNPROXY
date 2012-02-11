
#include <pthread.h>
#include <stdlib.h>
#include <linux/sched.h>

#include "workqueue.h"
#include "worker_pool.h"

struct workqueue {
	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
	int			nwait;
	int			nidle; /* init to 1 */
	struct list_head	work;
	struct worker_pool	*pool;
};

static int wait_on_busy(void)
{
	int opolicy;
	struct sched_param oparam, param;

	opolicy = sched_getscheduler(0);
	if (opolicy == -1)
		return -1;
	if (sched_getparam(0, &oparam) == -1)
		return -1;
	param = (struct sched_param){.sched_priority = 0};
	if (sched_setscheduler(0, SCHED_IDLE, &param) == -1)
		return -1;
	if (sched_yield() == -1)
		return -1;
	if (sched_setscheduler(0, opolicy, &oparam) == -1)
		return -1;

	return 0;
}

#define cmpxchg(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)
#define atomic_inc(ptr) (void)__sync_add_and_fetch(ptr, 1)
#define atomic_dec(ptr) (void)__sync_sub_and_fetch(ptr, 1)

static void worker_main(void *arg)
{
	struct workqueue *q = arg;
	struct work *work;
	int idle;

	idle = 1;
	while (1) {
		if (idle) {
			wait_on_busy();
			atomic_dec(&q->nidle);
		}

		/* pop a work. only one worker is allowed and necessory, other
		 * threads exit. */
		pthread_mutex_lock(&q->mutex);
		q->nwait++;
		while (list_empty(&q->work) && q->nwait == 1)
			pthread_cond_wait(&q->cond, &q->mutex);
		if (!list_empty(&q->work)) {
			work = list_first_entry(&q->work, struct work, list);
			list_del_init(&work->list);
			work->state = WORK_STATE_RUNNING;
		} else {
			work = NULL;
		}
		q->nwait--;
		pthread_mutex_unlock(&q->mutex);
		if (work == NULL)
			break;

		/* create a new worker to watch the current worker. if the
		 * current worker is blocked, or there is any other cpu
		 * can do the works, the new worker will run. */
		if (cmpxchg(&q->nidle, 0, 1) == 0) {
			if (worker_pool_do(q->pool, worker_main, q) < 0)
				atomic_dec(&q->nidle);
		}

		work->func(work->arg);
		(void)cmpxchg(&work->state, WORK_STATE_RUNNING,
			      WORK_STATE_PENDING);

		idle = cmpxchg(&q->nidle, 0, 1) == 0;
	}
}

void cancel_work(struct workqueue *wq, struct work *work)
{
	pthread_mutex_lock(&wq->mutex);
	if (!list_empty(&work->list)) {
		list_del_init(&work->list);
	}
	pthread_mutex_unlock(&wq->mutex);
	while (work->state == WORK_STATE_RUNNING)
		;
}
