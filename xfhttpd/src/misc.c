
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "misc.h"

/* record time and message in log file and exit */
void __die(const char *fmt, ...)
{
	va_list ap;
	int retval;
	char buf[1024];

	/* FIXME: save time */

	va_start(ap, fmt);
	retval = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (retval >= sizeof(buf))
		retval = sizeof(buf) - 1;
	if (retval == 0)
		exit(EXIT_FAILURE);
	if (buf[retval - 1] != '\n')
		buf[retval++] = '\n';

	/* Although stderr is redirected to /dev/null in daemon mode, this
	 * function maybe used in normal mode, before it enters in daemon
	 * mode. So this function try its best to output error messages to
	 * stderr */
	write(STDERR_FILENO, buf, retval);

	/* FIXME: save in file */

	exit(EXIT_FAILURE);
}
