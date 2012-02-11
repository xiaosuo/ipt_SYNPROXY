
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "serviced.h"

int main(int argc, char *argv[])
{
	struct serv_param param = {
		.flags	= SERV_F_LOG | SERV_F_RESTART,
		.delay	= 10,
		.uid	= 100,
		.gid	= 1000
	};
	pid_t pid;

	pid = serv_execv(NULL, argv, &param);
	if (pid < 0) {
		fprintf(stderr, "error\n");
		return EXIT_FAILURE;
	} else if (pid > 0) {
		fprintf(stdout, "instance's pid: %d\n", pid);
		return EXIT_FAILURE;
	}

	while (1) {
		sleep(3);
//		syslog(LOG_ERR, "xxx");
	}

	return EXIT_SUCCESS;
}
