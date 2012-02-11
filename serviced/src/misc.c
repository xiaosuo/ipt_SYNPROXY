
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
#include <unistd.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include "misc.h"
#include "serviced.h"

void strv_free(char **strv)
{
	if (strv != NULL) {
		char **pstrv;

		for (pstrv = strv; *pstrv != NULL; pstrv++)
			free(*pstrv);
		free(strv);
	}
}

char** strv_dup(char **strv)
{
	if (strv != NULL) {
		char **nstrv;
		int n;

		for (n = 0; strv[n] != NULL; n++)
			/* do nothing */;
		nstrv = calloc(n + 1, sizeof(char*));
		if (nstrv == NULL)
			return NULL;
		while (--n >= 0) {
			nstrv[n] = strdup(strv[n]);
			if (nstrv[n] == NULL) {
				strv_free(nstrv);
				return NULL;
			}
		}

		return nstrv;
	} else
		return NULL;
}

static const char *__get_env_from_strv(char *const envp[], const char *name)
{
	int i, len = strlen(name);

	for (i = 0; envp[i] != NULL; i++) {
		if (strncmp(envp[i], name, len) == 0 && envp[i][len] == '=')
			return envp[i] + len + 1;
	}

	return NULL;
}

int execvep(const char *filename, char *const argv[], char *const envp[])
{
	char cwd[MAXPATHLEN];
	const char *pwd;
	const char *path;
	gchar **tokens;
	int i;

	if (filename == NULL || argv == NULL)
		return -1;
	if (envp == NULL)
		return execve(filename, argv, envp);

	/* verify the current working directory, and change it if necessary */
	pwd = __get_env_from_strv(envp, "PWD");
	if (pwd != NULL) {
		if (getcwd(cwd, sizeof(cwd)) == NULL)
			return -1;
		if (strcmp(pwd, cwd) != 0 && chdir(pwd) != 0)
			return -1;
	}

	if (filename[0] == '/' || strncmp(filename, "./", 2) == 0 ||
	    strncmp(filename, "../", 3) == 0)
		return execve(filename, argv, envp);
	path = __get_env_from_strv(envp, "PATH");
	if (path == NULL)
		return execve(filename, argv, envp);
	tokens = g_strsplit(path, ":", 0);
	if (tokens == NULL)
		return -1;
	for (i = 0; tokens[i] != NULL; i++) {
		if (snprintf(cwd, sizeof(cwd), "%s/%s", tokens[i],
				filename) >= sizeof(cwd))
			break;
		execve(cwd, argv, envp);
	}

	g_strfreev(tokens);
	return -1;
}

/* uniqued: save the current pid to /var/run/prgname.pid and lock this file.
 * return the file descriptor points to lock/pid file if success.
 * return 0 if there is already one instance.
 * return -1 others.
 * XXX: it assumes the file descriptor 0 is used before calling this routine. */
int uniqued(const char *prgname)
{
	char buf[512];
	int fd, retval;

	g_return_val_if_fail(prgname != NULL, -1);

	retval = snprintf(buf, sizeof(buf), "/var/run/%s.pid", prgname);
	if (retval < 0 || retval >= sizeof(buf))
		return -1;
	retval = -1;
	if ((fd = open(buf, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP |
			S_IROTH)) < 0)
		goto out;
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno == EWOULDBLOCK)
			retval = 0;
		else
			unlink(buf);
		goto err;
	}
	if (ftruncate(fd, 0) < 0)
		goto err;
	retval = snprintf(buf, sizeof(buf), "%d\n", getpid());
	if (retval < 0 || retval >= sizeof(buf)) {
		retval = -1;
		goto err;
	}
	if (write(fd, buf, strlen(buf)) != strlen(buf))
		goto err;
	retval = fd;

out:
	return retval;

err:
	while (close(fd) < 0 && errno == EINTR)
		;
	goto out;
}

pid_t uniqued_pid(const char *prgname)
{
	FILE *fp;
	pid_t pid;
	int retval;
	char buf[512];
	
	g_return_val_if_fail(prgname != NULL, -1);

	retval = snprintf(buf, sizeof(buf), "/var/run/%s.pid", prgname);
	if (retval < 0 || retval >= sizeof(buf))
		return -1;
	fp = fopen(buf, "r");
	if (fp == NULL)
		return -1;
	retval = fscanf(fp, "%d", &pid);
	fclose(fp);
	if (retval != 1)
		return -1;
	
	if (snprintf(buf, sizeof(buf), "/proc/%d", pid) >= sizeof(buf))
		return -1;
	if (access(buf, R_OK) != 0)
		return -1;

	return pid;
}

int uniqued_exit(const char *prgname)
{
	char buf[512];
	int retval;

	g_return_val_if_fail(prgname != NULL, -1);

	retval = snprintf(buf, sizeof(buf), "/var/run/%s.pid", prgname);
	if (retval < 0 || retval >= sizeof(buf))
		return -1;
	if (remove(buf) != 0)
		return -1;

	return 0;
}

int close_all_fds(int skip_fd)
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
		if (close(i) < 0 && errno != EBADF)
			return -1;
	}

	return 0;
}

int serv_init_with_param(struct serv_param *param)
{
	struct rlimit rlim;

	/* change gid */
	if (param->gid != 0 && setregid(param->gid, param->gid) != 0)
			return -1;
	/* change uid */
	if (param->uid != 0 && setreuid(param->uid, param->uid) != 0)
			return -1;

	/* set memory threshold */
	if (param->mem_threshold > 0) {
		rlim.rlim_cur = param->mem_threshold;
		rlim.rlim_max = param->mem_threshold;
		if (setrlimit(RLIMIT_AS, &rlim) != 0)
			return -1;
	}

	/* set core dump */
	if (param->core_dump >= 0) {
		rlim.rlim_cur = param->core_dump;
		rlim.rlim_max = param->core_dump;
		if (setrlimit(RLIMIT_CORE, &rlim) != 0)
			return -1;
	}

	return 0;
}

char* read_all(int fd)
{
	char *buf, *tmp;
	int size, len, retval;

	size = 8192; /* default size */
	buf = malloc(size);
	if (buf == NULL)
		return NULL;
	len = 0;

	while (1) {
		retval = read(fd, buf + len, size - len - 1);
		if (retval < 0) {
			if (errno == EINTR)
				continue;
			goto err;
		} else if (retval == 0)
			break;
		len += retval;
		if (size - len < 4096) {
			if (size > 4096 * 16)
				goto err;
			size += 4096;
			tmp = realloc(buf, size);
			if (tmp == NULL)
				goto err;
			buf = tmp;
		}
	}
	buf[len] = '\0';

	return buf;

err:
	free(buf);
	return NULL;
}

int readn(int fd, void *buf, size_t count)
{
	char *ptr;
	int retval;

	for (ptr = buf; count > 0; ptr += retval, count -= retval) {
		while (1) {
			retval = read(fd, ptr, count);
			if (retval < 0) {
				if (errno == EINTR)
					continue;
				return ptr - (char*)buf;
			}
			break;
		}
	}

	return ptr - (char*)buf;
}

int write_all(int fd, const void *buf, size_t count)
{
	const char *ptr;
	int retval;

	for (ptr = buf; count > 0; ptr += retval, count -= retval) {
		while (1) {
			retval = write(fd, ptr, count);
			if (retval < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			break;
		}
	}

	return 0;
}

void daemonize(void)
{
	pid_t pid;
	struct sigaction act, oldact;

	/* Detach controlling terminal */
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);
	else if (pid > 0)
		_exit(EXIT_SUCCESS);
	setsid();

	/* Avoid owning controlling terminal again */
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, &oldact);
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);
	else if (pid > 0)
		_exit(EXIT_SUCCESS);
	/* Wait for the death of it's parent. */
	while (getppid() != 1)
		;
	sigaction(SIGHUP, &oldact, NULL);

	/* Deal with file operations */
	umask(0);
	if (chdir("/") < 0)
		exit(EXIT_FAILURE);
	if (close_all_fds(-1) < 0)
		exit(EXIT_FAILURE);
	if (open("/dev/null", O_RDWR) < 0 || dup(0) < 0 || dup(0) < 0)
		exit(EXIT_FAILURE);
}

int sleep_safe(long second)
{
	struct timespec ts = {.tv_sec = second};

	while (nanosleep(&ts, &ts) != 0) {
		if (errno != EINTR)
			return -1;
	}

	return 0;
}

int serv_param_check_user(struct serv_param *param, unsigned int uid,
		unsigned int gid)
{
	if (uid != param->uid || gid != param->gid) {
		if (param->uid == 0 && param->gid == 0) {
			/* use default value */
			param->uid = uid;
			param->gid = gid;
		} else if (uid != 0)
			return -EPERM;
	}

	return 0;
}
