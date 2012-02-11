
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#define RFC3164_TIME_FMT  "%b %e %T "

void __log(int level, const char *fmt, ...)
{
	va_list ap;
	char buf[1024];
	struct tm tm;
	time_t now;
	int retval;

	now = time(NULL);
	localtime_r(&now, &tm);
	retval = strftime(buf, sizeof(buf), RFC3164_TIME_FMT, &tm);

	va_start(ap, fmt);
	retval += vsnprintf(buf + retval, sizeof(buf) - retval, fmt, ap);
	va_end(ap);
	if (retval >= sizeof(buf))
		retval = sizeof(buf) - 1;
	if (buf[retval - 1] != '\n')
		buf[retval++] = '\n';

	/* FIXME: log handler */
	write(STDERR_FILENO, buf, retval);
}
