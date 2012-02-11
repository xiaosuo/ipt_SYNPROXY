
#ifndef _MISC_H_
#define _MISC_H_

#include "serviced.h"

void strv_free(char **strv);
char** strv_dup(char **strv);
int execvep(const char *filename, char *const argv[], char *const envp[]);
int uniqued(const char *prgname);
pid_t uniqued_pid(const char *prgname);
int uniqued_exit(const char *prgname);
int close_all_fds(int skip_fd);
int serv_init_with_param(struct serv_param *param);
char* read_all(int fd);
int readn(int fd, void *buf, size_t count);
int write_all(int fd, const void *buf, size_t count);
void daemonize(void);
int sleep_safe(long second);
int serv_param_check_user(struct serv_param *param, unsigned int uid,
		unsigned int gid);

#define BUG_ON(x) do { \
		if (x) { \
			syslog(LOG_ERR, "BUG at [%s:%d/%s]: " #x,  \
				__FILE__, __LINE__, __FUNCTION__); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)

#endif /* _MISC_H_ */
