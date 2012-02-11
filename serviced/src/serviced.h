
#ifndef _SERVICED_H_
#define _SERVICED_H_

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	SERV_F_LOG	= 0x01,
	SERV_F_RESTART	= 0x02,
};

struct serv_param {
	long		flags;		/* flags: SERV_F_X */
	long		mem_threshold;	/* max memory usage */
	long		core_dump;	/* max size of the core dump file */
	long		delay;		/* time before restarting */
	unsigned int	uid, gid;
};

pid_t serv_execve(const char *executable, char **argv, char **env,
		struct serv_param *param);
static inline pid_t serv_execv(const char *executable, char **argv,
		struct serv_param *param)
{
	extern char **environ;

	return serv_execve(executable, argv, environ, param);
}

int serv_kill(const char *name, int signo, long timeout);

#ifdef __cplusplus
}
#endif

#endif /* _SERVICED_H_ */
