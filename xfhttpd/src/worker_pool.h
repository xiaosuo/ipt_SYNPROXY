
#ifndef __THREAD_POOL_H
#define __THREAD_POOL_H

#include <time.h>

struct worker_pool;
struct worker_pool* create_worker_pool(int max, time_t life);
void worker_exit(void *arg);
int worker_pool_do(struct worker_pool *pool, void(*func)(void*), void *arg);
void destroy_worker_pool(struct worker_pool *pool);

#endif /* __THREAD_POOL_H */
