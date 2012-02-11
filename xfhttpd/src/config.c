
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "config.h"

struct config config = {
	.argv0	= NULL,
	.option = {
		.debug		= 0,
		.port		= 80,
		.host		= "localhost",
		.docroot	= ".",
	},
};

static const struct option long_options[] = {
	{
		.name		= "help",
		.has_arg	= 0,
		.flag		= NULL,
		.val		= 'h',
	},
	{
		.name		= "debug",
		.has_arg	= 0,
		.flag		= NULL,
		.val		= 'g',

	},
	{
		.name		= "port",
		.has_arg	= 1,
		.flag		= NULL,
		.val		= 'p',
	},
	{
		.name		= "host",
		.has_arg	= 1,
		.flag		= NULL,
		.val		= 'H',
	},
	{
		.name		= "docroot",
		.has_arg	= 1,
		.flag		= NULL,
		.val		= 'D',
	},
	{
		.name		= NULL,
		.has_arg	= 0,
		.flag		= NULL,
		.val		= 0,
	},
};

static const char *short_options = "hgp:H:D:";

static const char *help[] = {
	"show help message",
	"using debug mode",
	"lisen port, default '80'",
	"host name, default 'localhost'",
	"documentation root, default '.'",
};

static void show_help(int exit_code)
{
	const struct option *o;
	int i;

	fprintf(stderr, "Usage: %s [options...]\n\n", config.argv0);

	i = 0;
	for (o = &long_options[0]; o->name != NULL; o++) {
		fprintf(stderr, "  -%c, --%s%s\t%s\n",
			o->val, o->name, o->has_arg ? " arg" : "    ",
			help[i++]);
	}

	exit(exit_code);
}

void parse_args(int argc, char *argv[])
{
	int c;
	int option_index;

	config.argv0 = strdup(argv[0]);
	if (config.argv0 == NULL)
		die("Out Of Memory");

	while (1) {
		c = getopt_long(argc, argv, short_options, long_options,
				&option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			show_help(EXIT_SUCCESS);
			break;
		case 'g':
			config.option.debug = 1;
			break;
		case 'p':
			config.option.port = atoi(optarg);
			if (config.option.port <= 0 ||
			    config.option.port > 65535) {
				fprintf(stderr, "port must be in (0-65535]\n");
				show_help(EXIT_FAILURE);
			}
			break;
		case 'H':
			config.option.host = strdup(optarg);
			if (config.option.host == NULL) {
				fprintf(stderr, "Out Of Memory\n");
				show_help(EXIT_FAILURE);
			}
			break;
		case 'D':
			config.option.docroot = strdup(optarg);
			if (config.option.docroot == NULL) {
				fprintf(stderr, "Out Of Memory\n");
				show_help(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "\n");
			show_help(EXIT_FAILURE);
		}
	}

	if (optind != argc)
		show_help(EXIT_FAILURE);
}
