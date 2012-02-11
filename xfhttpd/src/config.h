
#ifndef __CONFIG_H
#define __CONFIG_H

struct config {
	const char *argv0;
	struct {
		int		debug;
		int		port;
		const char	*host;
		const char	*docroot;
	} option;
};

extern struct config config;

void parse_args(int argc, char *argv[]);

#endif /* __CONFIG_H */
