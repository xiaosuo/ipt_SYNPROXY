
#include <stdio.h>
#include <time.h>

#include "worker_pool.h"

void test(void *arg)
{
	int i;

	for (i = 0; i < (long)arg * 10; i++) {
		printf("%ld: %ld\n", time(NULL), (long)arg);
		sleep(1);
	}
}

int main()
{
	struct worker_pool *pool;

	pool = create_worker_pool(10, 10);
	worker_pool_do(pool, test, (void*)1);
	worker_pool_do(pool, test, (void*)2);
	destroy_worker_pool(pool);
	printf("%d\n", time(NULL));

	return 0;
}
