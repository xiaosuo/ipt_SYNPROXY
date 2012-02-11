
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "serviced.h"
#include "serviced_priv.h"
#include "misc.h"
#include "servmsg.h"

static pid_t servd_standalone(struct serv_param *param)
{
	if (serv_param_check_user(param, geteuid(), getegid()) != 0)
		return -1;

	if (serv_init_with_param(param) != 0)
		return -1;

	daemonize();

	return 0;
}

static int servd_connect(void)
{
	int sock;
	struct sockaddr_un addr;
	socklen_t addrlen;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (sizeof(addr.sun_path) <= strlen(SERVICED_SOCK_PATH))
		goto err;
	strcpy(&addr.sun_path[1], SERVICED_SOCK_PATH);
	addrlen = strlen(SERVICED_SOCK_PATH) + 1
			+ offsetof(struct sockaddr_un, sun_path);
	if (connect(sock, (struct sockaddr*)&addr, addrlen) < 0)
		goto err;
	
	return sock;

err:
	close(sock);
	return -1;
}

static pid_t servd_execve(const char *executable, char *argv[], char *env[],
		struct serv_param *param)
{
	int sock, n;
	char *msg;

	sock = servd_connect();
	if (sock < 0)
		return -1;

	msg = serv_msg_exec_new(executable, argv, env, param);
	if (msg == NULL)
		goto err;
	if (write_all(sock, msg, strlen(msg)) != 0)
		goto err2;
	serv_msg_exec_free(msg);
	/* shutdown write end to indicate the peer the whole message
	 * is sent. */
	if (shutdown(sock, SHUT_WR) != 0)
		goto err;

	/* FIXME: read error, but service is started successfully */
	msg = read_all(sock);
	if (msg == NULL)
		goto err;
	if (serv_msg_st_parse(&n, NULL, msg) != 0) {
		free(msg);
		goto err;
	}
	free(msg);

	return n;

err2:
	serv_msg_exec_free(msg);
err:
	close(sock);
	return -1;
}

pid_t serv_execve(const char *executable, char *argv[], char *env[],
		struct serv_param *param)
{
	pid_t pid;

	pid = uniqued_pid(PRGNAM);
	if (pid < 0) {/* no serviced is found, fallback to triditional method */
		fprintf(stderr, "<Warn> no serviced is valid\n");
		return servd_standalone(param);
	} else if (pid == getppid()) {
		char buf[32];
		int n;

		if (chdir("/") != 0)
			exit(EXIT_FAILURE);
		n = snprintf(buf, sizeof(buf), "%d", getpid());
		if (n < 0 || n >= sizeof(buf) ||
		    write(SERV_PIPE_FD, buf, n) != n ||
		    close(SERV_PIPE_FD) != 0)
			exit(EXIT_FAILURE);

		return 0;
	} else /* ask serviced to start this service instance */
		return servd_execve(executable, argv, env, param);
}

int serv_kill(const char *name, int signo, long timeout)
{
	pid_t pid;
	int sock, n;
	char *msg;

	pid = uniqued_pid(PRGNAM);
	if (pid < 0) {
		errno = EEXIST;
		return -1;
	}

	sock = servd_connect();
	if (sock < 0)
		return -1;

	msg = serv_msg_kill_new(name, signo, timeout);
	if (msg == NULL)
		goto err;
	if (write_all(sock, msg, strlen(msg)) != 0)
		goto err2;
	serv_msg_kill_free(msg);
	if (shutdown(sock, SHUT_WR) != 0)
		goto err;

	/* FIXME: read error, but service is killed successfully */
	msg = read_all(sock);
	if (msg == NULL)
		goto err;
	if (serv_msg_st_parse(&n, NULL, msg) != 0) {
		free(msg);
		goto err;
	}
	free(msg);
	return n;

err2:
	serv_msg_kill_free(msg);
err:
	close(sock);
	return -1;
}
