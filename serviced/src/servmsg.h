
#ifndef _SERVMSG_H_
#define _SERVMSG_H_

#include "serviced.h"

char* serv_msg_exec_new(const char *executable, char **argv, char **env,
		struct serv_param *param);
void serv_msg_exec_free(char *msg);
int serv_msg_exec_parse(char **executable, char ***argv, char ***env,
		struct serv_param *param, char *msg);

char* serv_msg_kill_new(const char *name, int signal, long timeo);
void serv_msg_kill_free(char *msg);
int serv_msg_kill_parse(char **name, int *signal, long *timeo, char *msg);

char* serv_msg_st_new(int code, const char *detail);
void serv_msg_st_free(char *msg);
int serv_msg_st_parse(int *code, char **detail, char *msg);

#endif /* _SERVMSG_H_ */
