
#include <stdlib.h>
#include <time.h>
#include <sys/times.h>
#include <pthread.h>

#include "list.h"
#include "worker_pool.h"

struct __work {
	struct list_head	list;
	void			(*func)(void*);
	void			*arg;
};

struct __worker {
	struct worker_pool	*pool;
};

enum worker_pool_state {
	WORKER_POOL_STATE_RUNNING,
	WORKER_POOL_STATE_DIEING,
};

struct worker_pool {
	pthread_attr_t		attr;
	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
	int			nworker;
	struct list_head	work;
	int			nwork;
	int			max;	/* max thread worker number */
	time_t			life;	/* idle time before die */
	enum worker_pool_state	state;
};

struct worker_pool* create_worker_pool(int max, time_t life)
{
	struct worker_pool *pool;

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL)
		return NULL;
	pthread_attr_init(&pool->attr);
	pthread_attr_setdetachstate(&pool->attr, PTHREAD_CREATE_DETACHED);
	pthread_mutex_init(&pool->mutex, NULL);
	pthread_cond_init(&pool->cond, NULL);
	INIT_LIST_HEAD(&pool->work);
	pool->max = max;
	pool->life = life;
	pool->state = WORKER_POOL_STATE_RUNNING;

	return pool;
}

void worker_exit(void *arg)
{
	struct __worker *worker = arg;
	struct worker_pool *pool = worker->pool;

	pthread_mutex_lock(&pool->mutex);
	pool->nwork--;
	if (--pool->nworker == 0 && pool->state == WORKER_POOL_STATE_DIEING)
		pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->mutex);
	free(worker);
	pthread_exit(NULL);
}

static void* worker_main(void *arg)
{
	struct timespec ts;
	int retval;
	struct __worker *worker = arg;
	struct worker_pool *pool = worker->pool;
	struct __work *work;
	void (*work_func)(void*);
	void *work_arg;

	pthread_mutex_lock(&pool->mutex);
	while (1) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += pool->life;
		retval = 0;
		while (list_empty(&pool->work) && retval == 0 &&
		       pool->state == WORKER_POOL_STATE_RUNNING)
			retval = pthread_cond_timedwait(&pool->cond,
							&pool->mutex, &ts);
		if (retval == 0 && pool->state == WORKER_POOL_STATE_RUNNING) {
			work = list_first_entry(&pool->work, struct __work,
						list);
			list_del(&work->list);
		} else {
			retval = -1;
			if (--pool->nworker == 0 &&
			    pool->state == WORKER_POOL_STATE_DIEING)
				pthread_cond_broadcast(&pool->cond);
		}
		pthread_mutex_unlock(&pool->mutex);
		if (retval != 0) {
			free(worker);
			break;
		}
		work_func = work->func;
		work_arg = work->arg;
		free(work);
		work_func(work_arg);
		pthread_mutex_lock(&pool->mutex);
		pool->nwork--;
	}

	return NULL;
}

static int __create_worker(struct worker_pool *pool)
{
	struct __worker *worker;
	pthread_t tid;

	worker = malloc(sizeof(*worker));
	if (worker == NULL)
		return -1;
	worker->pool = pool;
	if (pthread_create(&tid, &pool->attr, worker_main, worker) != 0) {
		free(worker);
		return -1;
	}
	pool->nworker++;

	return 1;
}

int worker_pool_do(struct worker_pool *pool, void(*func)(void*), void *arg)
{
	int retval = 0;

	pthread_mutex_lock(&pool->mutex);
	if (pool->state != WORKER_POOL_STATE_RUNNING)
		retval = -1;
	if (retval == 0 && pool->nworker <= pool->nwork) {
		if (pool->nworker >= pool->max)
			retval = -1;
		else
			retval = __create_worker(pool);
	}
	if (retval >= 0) {
		struct __work *work;

		work = malloc(sizeof(*work));
		if (work != NULL) {
			work->func = func;
			work->arg = arg;
			list_add_tail(&work->list, &pool->work);
			pool->nwork++;
			if (retval == 0)
				pthread_cond_signal(&pool->cond);
			else
				retval = 0;
		} else {
			retval = -1;
		}
	}
	pthread_mutex_unlock(&pool->mutex);

	return retval;
}

void destroy_worker_pool(struct worker_pool *pool)
{
	pthread_mutex_lock(&pool->mutex);
	pool->state = WORKER_POOL_STATE_DIEING;
	if (pool->nworker > 0)
		pthread_cond_broadcast(&pool->cond);
	while (pool->nworker != 0)
		pthread_cond_wait(&pool->cond, &pool->mutex);
	while (pool->nwork != 0) {
		struct __work *work;

		work = list_first_entry(&pool->work, struct __work, list);
		list_del(&work->list);
		pool->nwork--;
		free(work);
	}
	pthread_mutex_unlock(&pool->mutex);
	pthread_attr_destroy(&pool->attr);
	free(pool);
}
