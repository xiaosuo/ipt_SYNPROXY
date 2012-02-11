
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "serviced.h"
#include "serviced_priv.h"
#include "misc.h"
#include "servmsg.h"

/* #define DEBUG */
#define READ_TIMEOUT	3 /* in second */
#define WRITE_TIMEOUT	3 /* in second */

static int g_sig_pipe[2];
static GList *g_services = NULL;
static pthread_mutex_t g_services_lock = PTHREAD_MUTEX_INITIALIZER;

enum {
	SERV_ST_INIT = 0,
	SERV_ST_RUNNING,
	SERV_ST_DIED,
};

struct service {
	char			*name;
	char			*executable;
	char			**argv;
	char			**env;
	struct serv_param	param;
	pid_t			pid;
	int			state; /* running */
	pthread_mutex_t		lock; /* protect this service except for user */
	volatile gint		user; /* how many users use it */
	pthread_cond_t		waiter;
};

static int service_cmp_name(struct service *serv, const char *name)
{
	int retval;

	pthread_mutex_lock(&serv->lock);
	retval = strcmp(serv->name, name);
	pthread_mutex_unlock(&serv->lock);

	return retval;
}

static struct service* __service_find_by_name(const char *name)
{
	GList *list;

	list = g_list_find_custom(g_services, name,
			(GCompareFunc)service_cmp_name);
	
	return list != NULL ? list->data : NULL;
}

static struct service *service_find_and_get_by_name(const char *name)
{
	struct service *serv;

	pthread_mutex_lock(&g_services_lock);
	serv = __service_find_by_name(name);
	if (serv != NULL)
		g_atomic_int_inc(&serv->user);
	pthread_mutex_unlock(&g_services_lock);

	return serv;
}

static int service_cmp_pid(struct service *serv, pid_t *pid)
{
	int retval;

	pthread_mutex_lock(&serv->lock);
	retval = serv->pid - *pid;
	pthread_mutex_unlock(&serv->lock);

	return retval;
}

static struct service *__service_find_and_get_by_pid(pid_t pid)
{
	GList *list;
	struct service *serv = NULL;

	list = g_list_find_custom(g_services, &pid,
			(GCompareFunc)service_cmp_pid);
	if (list != NULL) {
		serv = list->data;
		g_atomic_int_inc(&serv->user);
	}

	return serv;
}

static int service_add(struct service *serv)
{
	int retval = 0;

	pthread_mutex_lock(&g_services_lock);
	if (__service_find_by_name(serv->name) == NULL) {
		g_services = g_list_append(g_services, serv);
		g_atomic_int_inc(&serv->user);
	} else
		retval = -EEXIST;
	pthread_mutex_unlock(&g_services_lock);

	return retval;
}

static struct service* service_new(const char *executable, char **argv,
		char **env, struct serv_param *param)
{
	struct service *serv;
	char *ptr;

	serv = calloc(1, sizeof(*serv));
	if (serv == NULL)
		return NULL;
	serv->executable = strdup(executable);
	if (serv->executable == NULL)
		goto err;
	serv->argv = strv_dup(argv);
	if (serv->argv == NULL)
		goto err2;
	serv->env = strv_dup(env);
	if (serv->env == NULL)
		goto err3;
	ptr = strrchr(serv->argv[0], '/');
	if (ptr == NULL)
		ptr = serv->argv[0];
	else
		ptr++;
	serv->name = strdup(ptr);
	if (serv->name == NULL)
		goto err4;
	serv->param = *param;
	pthread_mutex_init(&serv->lock, NULL);
	g_atomic_int_set(&serv->user, 1);
	pthread_cond_init(&serv->waiter, NULL);

	return serv;

err4:
	strv_free(serv->env);
err3:
	strv_free(serv->argv);
err2:
	free(serv->executable);
err:
	free(serv);
	return NULL;
}

static void service_put(struct service *serv)
{
	if (!g_atomic_int_dec_and_test(&serv->user))
		return;

	pthread_cond_destroy(&serv->waiter);
	pthread_mutex_destroy(&serv->lock);
	free(serv->name);
	free(serv->executable);
	strv_free(serv->argv);
	strv_free(serv->env);
	free(serv);
}

static void service_may_del_and_put(struct service *serv)
{
	pthread_mutex_lock(&g_services_lock);
	if (g_list_find(g_services, serv) != NULL) {
		g_services = g_list_remove(g_services, serv);
		g_atomic_int_add(&serv->user, -1);
	}
	pthread_mutex_unlock(&g_services_lock);

	service_put(serv);
}

static void service_foreach(void(*func)(struct service *, void*), void *data)
{
	pthread_mutex_lock(&g_services_lock);
	g_list_foreach(g_services, (GFunc)func, data);
	pthread_mutex_unlock(&g_services_lock);
}

static inline int fd_set_nonblock(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

static int servd_listen(int backlog)
{
	int sock;
	struct sockaddr_un addr;
	socklen_t addrlen;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	if (fd_set_nonblock(sock) != 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (sizeof(addr.sun_path) <= strlen(SERVICED_SOCK_PATH))
		goto err;
	strcpy(&addr.sun_path[1], SERVICED_SOCK_PATH);
	addrlen = strlen(SERVICED_SOCK_PATH) + 1
			+ offsetof(struct sockaddr_un, sun_path);
	if (bind(sock, (struct sockaddr*)&addr, addrlen) != 0)
		goto err;
	if (listen(sock, backlog) != 0)
		goto err;

	return sock;

err:
	close(sock);
	return -1;
}

/* return -1 on error, and errno will be set accordingly. */
static int read_timeout(int fd, void *buf, size_t count, time_t sec)
{
	fd_set rdset;
	struct timeval tv;
	int retval;

	FD_ZERO(&rdset);
	FD_SET(fd, &rdset);
	tv.tv_sec = sec;
	tv.tv_usec = 0;
	retval = select(fd + 1, &rdset, NULL, NULL, &tv);
	if (retval < 0)
		return retval;
	if (retval == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	
	return read(fd, buf, count);
}

/* return pid of the child process on success, otherwise error. */
static int __serv_start(struct service *serv)
{
	int fds[2], pid;

	if (pipe(fds) != 0)
		return -errno;
	pthread_mutex_lock(&serv->lock);
	serv->pid = pid = fork();
	pthread_mutex_unlock(&serv->lock);
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return -errno;
	} else if (pid == 0) {
		/* reset signal handler */
		if (signal(SIGCHLD, SIG_DFL) == SIG_ERR ||
		    signal(SIGPIPE, SIG_DFL) == SIG_ERR ||
		    signal(SIGTERM, SIG_DFL) == SIG_ERR)
		    	exit(EXIT_FAILURE);

		/* close all the file descriptors opened */
		if (close_all_fds(fds[1]) != 0)
		    	exit(EXIT_FAILURE);

		/* the file descriptor of the write end of the pipe must
		 * be SERV_PIPE_FD */
		if (fds[1] != SERV_PIPE_FD &&
		    (dup2(fds[1], SERV_PIPE_FD) < 0 || close(fds[1]) < 0))
		    	exit(EXIT_FAILURE);
		/* redirect stdin/stdout/stderr to /dev/null */
		if (open("/dev/null", O_RDWR) < 0 || dup(0) < 0 || dup(0) < 0)
		    	exit(EXIT_FAILURE);

		if (serv_init_with_param(&serv->param) != 0)
		    	exit(EXIT_FAILURE);

		/* execute the binary file */
		execvep(serv->executable, serv->argv, serv->env);

		exit(EXIT_FAILURE);
	} else { /* parent process */
		char buf[32];
		int len, retval;

		close(fds[1]);
		len = read_timeout(fds[0], buf, sizeof(buf) - 1, READ_TIMEOUT);
		close(fds[0]);
		if (len <= 0) {
			if (len < 0)
				retval = -errno;
			else
				retval = -EFAULT;
			goto err;
		}
		buf[len] = '\0';
		retval = atoi(buf);
		if (retval <= 0 || retval != pid) {
			if (retval >= 0)
				retval = -EFAULT;
			goto err;
		}

		pthread_mutex_lock(&serv->lock);
		if (serv->state == SERV_ST_INIT)
			serv->state = SERV_ST_RUNNING;
		else /* died early */
			pid = -EFAULT;
		pthread_mutex_unlock(&serv->lock);

		return pid;
	err:
		pthread_mutex_lock(&g_services_lock);
		pthread_mutex_lock(&serv->lock);
		if (serv->pid && serv->state != SERV_ST_DIED)
			kill(pid, SIGKILL);
		pthread_mutex_unlock(&serv->lock);
		pthread_mutex_unlock(&g_services_lock);
		return retval;
	}
}

static int serv_start(const char *executable, char **argv, char **env,
		struct serv_param *param, int fd)
{
	struct service *serv;
	int retval;
	struct ucred cred;
	socklen_t optlen;

	optlen = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &optlen) != 0)
		return -errno;
	if ((retval = serv_param_check_user(param, cred.uid, cred.gid)) != 0)
		return retval;
	
	serv = service_new(executable, argv, env, param);
	if (serv == NULL)
		return -ENOMEM;
	if ((retval = service_add(serv)) != 0 ||
	    (retval = __serv_start(serv)) <= 0) {
		service_may_del_and_put(serv);
		return retval;
	}
	service_put(serv);

	return retval;
}

static int serv_stop(const char *name, int signo, long timeout, int fd)
{
	struct service *serv;
	struct ucred cred;
	socklen_t optlen;
	int retval;

	serv = service_find_and_get_by_name(name);
	if (serv == NULL)
		return -EEXIST;

	/* check permission */
	optlen = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &optlen) != 0) {
		retval = -errno;
		goto out;
	}
	retval = 0;
	if (cred.uid != 0) {
		pthread_mutex_lock(&serv->lock);
		if (cred.uid != serv->param.uid ||
		    cred.gid != serv->param.gid)
			retval = -EPERM;
		pthread_mutex_unlock(&serv->lock);
	}
	if (retval != 0)
		goto out;

	/* send signal<signo> */
	/* hold service lock for avoiding race condition: 
	 * wait before killing, and another process appears too quickly. */
	pthread_mutex_lock(&g_services_lock);
	pthread_mutex_lock(&serv->lock);
	if (serv->pid && serv->state == SERV_ST_RUNNING)
		retval = kill(serv->pid, signo);
	else 
		retval = -EEXIST;
	pthread_mutex_unlock(&serv->lock);
	pthread_mutex_unlock(&g_services_lock);
	if (retval != 0)
		goto out;

	/* wait for the death of the process */
	pthread_mutex_lock(&serv->lock);
	if (timeout < 0)
		retval = pthread_cond_wait(&serv->waiter, &serv->lock);
	else {
		struct timespec ts;

		retval = clock_gettime(CLOCK_REALTIME, &ts);
		if (retval == 0) {
			ts.tv_sec += timeout;
			ts.tv_nsec = 0;
			retval = pthread_cond_timedwait(&serv->waiter,
					&serv->lock, &ts);
		}
	}
	pthread_mutex_unlock(&serv->lock);
out:
	service_put(serv);
	return retval > 0 ? -retval : retval;
}

static void* worker(void *arg)
{
	int fd = *(int*)arg, retval = -1;
	struct timeval timeo;
	socklen_t optlen = sizeof(timeo);
	char *executable, *msg, **argv, **env;
	struct serv_param param;
	char buf[256];

	free(arg);

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = READ_TIMEOUT;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, optlen) != 0)
		goto out;
	timeo.tv_sec = WRITE_TIMEOUT;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, optlen) != 0)
		goto out;

	msg = read_all(fd);
	if (msg == NULL)
		goto out;
	if (serv_msg_exec_parse(&executable, &argv, &env, &param, msg) == 0) {
		free(msg);

		retval = serv_start(executable, argv, env, &param, fd);
		free(executable);
		strv_free(argv);
		strv_free(env);
	} else {
		char *name = NULL;
		int signo;
		long timeout;

		if (serv_msg_kill_parse(&name, &signo, &timeout, msg) != 0) {
			free(msg);
			goto out;
		}
		free(msg);

		retval = serv_stop(name, signo, timeout, fd);
		free(name);
	}

	/* send the result back */
	buf[0] = '\0';
	strerror_r(-retval, buf, sizeof(buf));
	msg = serv_msg_st_new(retval, buf);
	write_all(fd, msg, strlen(msg));
	serv_msg_st_free(msg);
out:
	close(fd);
	return NULL;
}

static int do_serv(int sock, pthread_attr_t *attr)
{
	pthread_t tid;
	int *psock;
	int retval;
	
	retval = -ENOMEM;
	psock = malloc(sizeof(int));
	if (psock == NULL)
		goto err;
	*psock = sock;
	if ((retval = pthread_create(&tid, attr, worker, psock)) != 0)
		goto err2;
	return 0;

err2:
	free(psock);
err:
	close(sock);
	return retval > 0 ? -retval : retval;
}

static void *restarter(void *args)
{
	struct service *serv = args;
	long delay;

	pthread_mutex_lock(&serv->lock);
	delay = serv->param.delay;
	pthread_mutex_unlock(&serv->lock);
	if (delay > 0 && sleep_safe(delay) != 0)
			return NULL;
	if (__serv_start(serv) <= 0) {
		service_may_del_and_put(serv);
		return NULL;
	}
	service_put(serv);
	return NULL;
}

static int do_restart(struct service *serv, pthread_attr_t *attr)
{
	pthread_t tid;

	if (pthread_create(&tid, attr, restarter, serv) != 0) {
		service_may_del_and_put(serv);
		return -1;
	}

	return 0;
}

static void signal_handler(int signo)
{
	if (write_all(g_sig_pipe[1], &signo, sizeof(signo)) != 0) {
		syslog(LOG_ERR, "write: %m");
		abort();
	}
}

static void reclaim_children(pthread_attr_t *attr)
{
	pid_t pid;
	int status;
	struct service *serv;
	enum {
		ACT_NONE = 0,
		ACT_DELETE,
		ACT_RESTART
	} action;

	while (1) {
		pthread_mutex_lock(&g_services_lock);
		pid = waitpid(-1, &status, WNOHANG);
		if (pid > 0) {
			serv = __service_find_and_get_by_pid(pid);
			if (serv != NULL) {
				pthread_mutex_lock(&serv->lock);
				/* assign 0 to serv->pid to avoid race
				 * condition */
				serv->pid = 0;
				pthread_mutex_unlock(&serv->lock);
			}
		}
		pthread_mutex_unlock(&g_services_lock);
		if (pid <= 0)
			break;
		/* maybe deleted by service_start() */
		if (serv == NULL)
			continue;

		/* acquire the lock before accessing the internal variables */
		pthread_mutex_lock(&serv->lock);

		action = ACT_NONE;
		/* check service state */
		if (serv->state != SERV_ST_RUNNING) {
			/* died early */
			serv->state = SERV_ST_DIED;
			goto next;
		}
		serv->state = SERV_ST_INIT;

		action = ACT_DELETE;
		if (WIFEXITED(status)) {
			syslog(LOG_INFO, "%s exit with %d", serv->argv[0],
					WEXITSTATUS(status));
			goto next;
		} else if (WIFSIGNALED(status)) {
			syslog(LOG_INFO, "%s exit due to signal: %d",
					serv->argv[0], WTERMSIG(status));
			/* terminate normally */
			if (WTERMSIG(status) == SIGTERM)
				goto next;
		}
		if (serv->param.flags & SERV_F_LOG) {
			/* FIXME: special log */
			syslog(LOG_INFO, "%s exit", serv->argv[0]);
		}
		if (serv->param.flags & SERV_F_RESTART)
			action = ACT_RESTART;

	next:
		pthread_cond_broadcast(&serv->waiter);
		pthread_mutex_unlock(&serv->lock);
		switch (action) {
		case ACT_NONE:
			service_put(serv);
			break;
		case ACT_DELETE:
			service_may_del_and_put(serv);
			break;
		case ACT_RESTART:
			do_restart(serv, attr);
			break;
		default:
			break;
		}
		continue;
	}

	if (pid == -1  && errno != ECHILD)
		syslog(LOG_ERR, "waitpid: %m");
}

static void service_kill(struct service *serv, void *data)
{
	pthread_mutex_lock(&serv->lock);
	if (serv->pid && serv->state != SERV_ST_DIED)
		kill(serv->pid, SIGTERM);
	pthread_mutex_unlock(&serv->lock);
}

int main(int argc, char *argv[])
{
	int listen_sock, sock, lockfd, max_fd, retval;
	sigset_t new, old;
	fd_set rdset;
	pthread_attr_t attr;

	#ifndef DEBUG
	daemonize();
	#endif

	/* only one serviced instance is allowed */
	lockfd = uniqued(PRGNAM);
	if (lockfd < 0) {
		syslog(LOG_ERR, "uniqued: %m");
		return EXIT_FAILURE;
	} else if (lockfd == 0) {
		syslog(LOG_ERR, "there is already one instance");
		return EXIT_FAILURE;
	}

	/* create an anonymous pipe to deal with signals */
	if (pipe(g_sig_pipe) < 0) {
		syslog(LOG_ERR, "pipe: %m");
		return EXIT_FAILURE;
	}
	if (fd_set_nonblock(g_sig_pipe[0]) != 0 ||
	    fd_set_nonblock(g_sig_pipe[1]) != 0) {
		syslog(LOG_ERR, "can't set pipe in nonblock status");
		return EXIT_FAILURE;
	}
	if (signal(SIGCHLD, signal_handler) == SIG_ERR ||
	    signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
	    signal(SIGTERM, signal_handler) == SIG_ERR) {
		syslog(LOG_ERR, "signal: %m");
		return EXIT_FAILURE;
	}

	listen_sock = servd_listen(10);
	if (listen_sock < 0) {
		syslog(LOG_ERR, "servd_listen: %m");
		return EXIT_FAILURE;
	}

	if ((retval = pthread_attr_init(&attr)) != 0) {
		syslog(LOG_ERR, "pthread_attr_init exit with: %d", retval);
		return EXIT_FAILURE;
	}
	retval = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (retval != 0) {
		syslog(LOG_ERR, "pthread_attr_setdetachstate exit with: %d",
				retval);
		return EXIT_FAILURE;
	}

	FD_ZERO(&rdset);
	FD_SET(g_sig_pipe[0], &rdset);
	FD_SET(listen_sock, &rdset);
	max_fd = MAX(listen_sock, g_sig_pipe[0]);
	/* block SIGCHLD, then the process will be simpler */
	if (sigemptyset(&new) != 0 || sigaddset(&new, SIGCHLD) != 0) {
		syslog(LOG_ERR, "sigset operation: %m");
		return EXIT_FAILURE;
	}
	if (sigprocmask(SIG_BLOCK, &new, &old) != 0) {
		syslog(LOG_ERR, "sigprocmask: %m");
		return EXIT_FAILURE;
	}

	while (1) {
		/* call select with SIGCHLD unblocked */
		if (sigprocmask(SIG_SETMASK, &old, NULL) != 0) {
			syslog(LOG_ERR, "sigprocmask: %m");
			return EXIT_FAILURE;
		}
		while (select(max_fd + 1, &rdset, NULL, NULL, NULL) < 0) {
			if (errno != EINTR)
				syslog(LOG_ERR, "select: %m");
		}
		if (sigprocmask(SIG_BLOCK, &new, &old) != 0) {
			syslog(LOG_ERR, "sigprocmask: %m");
			return EXIT_FAILURE;
		}

		/* process request from user */
		if (FD_ISSET(listen_sock, &rdset)) {
			sock = accept(listen_sock, NULL, NULL);
			if (sock < 0)
				syslog(LOG_ERR, "accept: %m");
			else {
				if ((retval = do_serv(sock, &attr)) != 0) {
					char buf[256];
					
					buf[0] = '\0';
					strerror_r(-retval, buf, sizeof(buf));
					syslog(LOG_ERR, "do_serv: %s", buf);
				}
			}
		} else
			FD_SET(listen_sock, &rdset);

		/* some children died */
		if (FD_ISSET(g_sig_pipe[0], &rdset)) {
			int signo = -1;

			while ((retval = readn(g_sig_pipe[0], &signo,
					sizeof(signo))) == sizeof(signo)) {
				if (signo == SIGTERM)
					goto out;
			}
			if (errno != EAGAIN) {
				syslog(LOG_ERR, "read: %m");
				abort();
			} else if (retval != 0) {
				syslog(LOG_ERR, "read part of signo");
				abort();
			}
			if (signo == SIGCHLD)
				reclaim_children(&attr);
		} else
			FD_SET(g_sig_pipe[0], &rdset);
	}

out:
	/* kill all the services */
	service_foreach(service_kill, NULL);
	uniqued_exit(PRGNAM);

	return EXIT_SUCCESS;
}
