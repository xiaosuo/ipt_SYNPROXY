/* FIXME: start/restart/stop special service */

#include <stdlib.h>
#include <stdio.h>
#include <serviced.h>
#include <signal.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>

const static struct option opts[] = {
	{ "signal", 1, 0, 's' },
	{ "timeout", 1, 0, 't' },
	{ 0 } };

static void help(const char *prg)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]... start|stop|restart program...\n"
		"\n"
		"  -s, --signal    the signal to stop program, default %d\n"
		"  -t, --timeout   the time waiting for program exiting, default %d\n",
		prg, SIGTERM, 3);
}

int main(int argc, char *argv[])
{
	int retval, signo = SIGTERM;
	long timeout = 3;
	struct serv_param param = {
		.flags		= SERV_F_LOG | SERV_F_RESTART,
		.mem_threshold	= 2L * 1024L * 1024L * 1024L,
		.core_dump	= 1024 * 1024 * 10,
		.delay		= 0,
		.uid		= 0,
		.gid		= 0
	};

	while (1) {
		retval = getopt_long(argc, argv, "s:t:", opts, NULL);
		if (retval == -1)
			break;
		switch (retval) {
		case 's':
			if ((signo = atoi(optarg)) <= 0 || signo > 32) {
				help(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			timeout = atol(optarg);
			if (timeout < 0) {
				help(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			help(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (optind > argc - 2) {
		help(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[optind], "start") == 0) {
		optind++;
		serv_execv(argv[optind], &argv[optind], &param);
	} else if (strcmp(argv[optind], "stop") == 0) {
		optind++;
		serv_kill(argv[optind], signo, timeout);
	} else if (strcmp(argv[optind], "restart") == 0) {
		optind++;
		serv_kill(argv[optind], signo, timeout);
		serv_execv(argv[optind], &argv[optind], &param);
	} else {
		help(argv[0]);
		exit(EXIT_FAILURE);
	}

	return 0;
}
