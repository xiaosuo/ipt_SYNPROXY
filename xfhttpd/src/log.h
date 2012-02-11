
#ifndef __LOG_H
#define __LOG_H

enum {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_EVENT,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERR,
};

void __log(int level, const char *fmt, ...);

#define log_debug(fmt, args...) __log(LOG_LEVEL_DEBUG, fmt, ##args)
#define log_event(fmt, args...) __log(LOG_LEVEL_EVENT, fmt, ##args)
#define log_warn(fmt, args...) __log(LOG_LEVEL_WARN, fmt, ##args)
#define log_err(fmt, args...) __log(LOG_LEVEL_ERR, fmt, ##args)

#endif /* __LOG_H */
