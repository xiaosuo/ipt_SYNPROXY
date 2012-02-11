
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "daemon.h"

/* uniqued: save the current pid to /var/run/prgname.pid and lock this file.
 * return 0 on success.
 * return -1 on error. */
static int uniqued(const char *prgname)
{
	char buf[512];
	int fd, retval;

	retval = snprintf(buf, sizeof(buf), "/var/run/%s.pid", prgname);
	if (retval < 0 || retval >= sizeof(buf))
		return -1;
	if ((fd = open(buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP |
		       S_IROTH)) < 0)
		return -1;
	if (flock(fd, LOCK_EX | LOCK_NB) < 0)
		goto err;
	if (ftruncate(fd, 0) < 0)
		goto err;
	retval = snprintf(buf, sizeof(buf), "%d\n", getpid());
	if (retval < 0 || retval >= sizeof(buf))
		goto err;
	if (write(fd, buf, strlen(buf)) != strlen(buf))
		goto err;

	return 0;

err:
	while (close(fd) < 0 && errno == EINTR)
		;
	return -1;
}

static int close_all_fds(int skip_fd)
{
	struct rlimit rlim;
	int i;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		return -1;
	if (rlim.rlim_cur == RLIM_INFINITY)
		rlim.rlim_cur = 1024; /* use the default value */
	for (i = 0; i < rlim.rlim_cur; i++) {
		if (i == skip_fd) /* skip it */
			continue;
		while (close(i) < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EBADF)
				break;
			else
				return -1;
		}
	}

	return 0;
}

int daemonize(const char *name)
{
	pid_t pid;
	struct sigaction act, oldact;

	/* Detach controlling terminal */
	if ((pid = fork()) < 0)
		return -1;
	else if (pid > 0)
		_exit(EXIT_SUCCESS);
	setsid();

	/* Avoid owning controlling terminal again */
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, &oldact);
	if ((pid = fork()) < 0)
		return -1;
	else if (pid > 0)
		_exit(EXIT_SUCCESS);
	/* Wait for the death of it's parent. */
	while (getppid() != 1)
		;
	sigaction(SIGHUP, &oldact, NULL);

	/* Deal with file operations */
	umask(0);
	if (chdir("/") < 0)
		return -1;
	if (close_all_fds(-1) < 0)
		return -1;
	if (open("/dev/null", O_RDWR) < 0 || dup(0) < 0 || dup(0) < 0)
		return -1;

	return uniqued(name);
}
