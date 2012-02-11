
#include <string.h>
#include <glib.h>
#include <stdlib.h>
#include <stdio.h>

#include "misc.h"
#include "servmsg.h"

/* service execution message */
char* serv_msg_exec_new(const char *executable, char **argv, char **env,
		struct serv_param *param)
{
	GString *output;
	gchar *str;
	int i, argc, envc;

	g_return_val_if_fail(argv != NULL, NULL);
	g_return_val_if_fail(env != NULL, NULL);
	g_return_val_if_fail(param != NULL, NULL);

	/* calculate the number of arguments and environment variables */
	for (i = 0; argv[i] != NULL; i++)
		/* do nothing */;
	argc = i;
	g_return_val_if_fail(argc > 0, NULL);

	for (i = 0; env[i] != NULL; i++)
		/* do nothing */;
	envc = i;

	output = g_string_new("<service type=\"execute\">");
	g_return_val_if_fail(output != NULL, NULL);

	str = g_markup_printf_escaped("<executable>%s</executable>",
			executable == NULL ? argv[0] : executable);
	if (str == NULL)
		return g_string_free(output, TRUE);
	g_string_append(output, str);
	g_free(str);

	g_string_append_printf(output, "<arguments number=\"%d\">", argc);
	for (i = 0; i < argc; i++) {
		str = g_markup_printf_escaped("<argument>%s</argument>",
				argv[i]);
		if (str == NULL)
			return g_string_free(output, TRUE);
		g_string_append(output, str);
		g_free(str);
	}
	g_string_append(output, "</arguments>");

	g_string_append_printf(output, "<environments number=\"%d\">", envc);
	for (i = 0; i < envc; i++) {
		str = g_markup_printf_escaped("<environment>%s</environment>",
				env[i]);
		if (str == NULL)
			return g_string_free(output, TRUE);
		g_string_append(output, str);
		g_free(str);
	}
	g_string_append(output, "</environments>");

	g_string_append_printf(output, "<memthreshold>%ld</memthreshold>"
			"<flags>%ld</flags>"
			"<delay>%ld</delay>"
			"<coredump>%ld</coredump>"
			"<uid>%u</uid>"
			"<gid>%u</gid>",
			param->mem_threshold,
			param->flags,
			param->delay,
			param->core_dump,
			param->uid,
			param->gid);

	g_string_append(output, "</service>");

	return g_string_free(output, FALSE);
}

void serv_msg_exec_free(char *msg)
{
	g_free(msg);
}

struct __serv_msg_exec_parse_data {
	char			*executable;
	int			argc;
	char			**argv;
	int			envc;
	char			**env;
	struct serv_param	param;
};

static void __serv_msg_exec_parse_data_free(gpointer data)
{
	struct __serv_msg_exec_parse_data *pdata = data;

	if (pdata->executable != NULL)
		free(pdata->executable);
	strv_free(pdata->argv);
	strv_free(pdata->env);
}

static void __serv_msg_exec_start_element(GMarkupParseContext *context,
		const gchar *element_name, const gchar **attribute_names,
		const gchar **attribute_values, gpointer user_data,
		GError **error)
{
	struct __serv_msg_exec_parse_data *pdata = user_data;
	int i, n;

	if (strcmp(element_name, "service") == 0) {
		const gchar *type = NULL;

		for (i = 0; attribute_names[i] != NULL; i++) {
			if (strcmp(attribute_names[i], "type") == 0) {
				type = attribute_values[i];
				break;
			}
		}
		if (type == NULL || strcmp(type, "execute") != 0)
			goto err;
	} else if (strcmp(element_name, "arguments") == 0) {
		if (pdata->argc != 0 || pdata->argv != NULL)
			goto err;
		for (i = 0; attribute_names[i] != NULL; i++) {
			if (strcmp(attribute_names[i], "number") == 0) {
				n = pdata->argc = atoi(attribute_values[i]);
				if (n < 1)
					goto err;
				pdata->argv = calloc(n + 1, sizeof(char*));
				break;
			}
		}
		if (pdata->argc == 0 || pdata->argv == NULL)
			goto err;
	} else if (strcmp(element_name, "environments") == 0) {
		if (pdata->envc != 0 || pdata->env != NULL)
			goto err;
		for (i = 0; attribute_names[i] != NULL; i++) {
			if (strcmp(attribute_names[i], "number") == 0) {
				n = pdata->envc = atoi(attribute_values[i]);
				if (n < 0)
					goto err;
				pdata->env = calloc(n + 1, sizeof(char*));
				break;
			}
		}
		if (pdata->env == NULL)
			goto err;
	}

	return;

err:
	*error = g_error_new(G_MARKUP_ERROR,
			G_MARKUP_ERROR_INVALID_CONTENT, "Invalid content");
}

static void __serv_msg_exec_text(GMarkupParseContext *context, const gchar *text,
		gsize text_len, gpointer user_data, GError **error)
{
	struct __serv_msg_exec_parse_data *pdata = user_data;
	const gchar *element_name = g_markup_parse_context_get_element(context);

	if (strcmp(element_name, "executable") == 0) {
		if (pdata->executable != NULL)
			goto err;
		pdata->executable = strdup(text);
		if (pdata->executable == NULL)
			goto err;
	} else if (strcmp(element_name, "argument") == 0) {
		int i;

		if (pdata->argv == NULL)
			goto err;
		for (i = 0; i < pdata->argc; i++) {
			if (pdata->argv[i] == NULL) {
				pdata->argv[i] = strdup(text);
				break;
			}
		}
		if (i == pdata->argc || pdata->argv[i] == NULL)
			goto err;
	} else if (strcmp(element_name, "environment") == 0) {
		int i;

		if (pdata->env == NULL)
			goto err;
		for (i = 0; i < pdata->envc; i++) {
			if (pdata->env[i] == NULL) {
				pdata->env[i] = strdup(text);
				break;
			}
		}
		if (i == pdata->envc || pdata->env[i] == NULL)
			goto err;
	} else if (strcmp(element_name, "memthreshold") == 0)
		pdata->param.mem_threshold = strtol(text, NULL, 10);
	else if (strcmp(element_name, "flags") == 0)
		pdata->param.flags = strtol(text, NULL, 10);
	else if (strcmp(element_name, "delay") == 0)
		pdata->param.delay = strtol(text, NULL, 10);
	else if (strcmp(element_name, "coredump") == 0)
		pdata->param.core_dump = strtol(text, NULL, 10);
	else if (strcmp(element_name, "uid") == 0)
		pdata->param.uid = strtoul(text, NULL, 10);
	else if (strcmp(element_name, "gid") == 0)
		pdata->param.gid = strtoul(text, NULL, 10);

	return;

err:
	*error = g_error_new(G_MARKUP_ERROR,
			G_MARKUP_ERROR_INVALID_CONTENT, "Invalid content");
}

static GMarkupParser __serv_msg_exec_parser = {
	.start_element	= __serv_msg_exec_start_element,
	.text		= __serv_msg_exec_text
};

int serv_msg_exec_parse(char **executable, char ***argv, char ***env,
		struct serv_param *param, char *msg)
{
	GMarkupParseContext *context;
	struct __serv_msg_exec_parse_data data;
	GError *error = NULL;
	int i, retval = -1;

	memset(&data, 0, sizeof(data));
	context = g_markup_parse_context_new(&__serv_msg_exec_parser, 0, &data,
			__serv_msg_exec_parse_data_free);
	if (context == NULL)
		return -1;
	if (!g_markup_parse_context_parse(context, msg, strlen(msg), &error) ||
	    !g_markup_parse_context_end_parse(context, &error)) {
		g_markup_parse_context_free(context);
		return -1;
	}

	if (data.executable == NULL)
		goto out;
	for (i = 0; data.argv[i] != NULL; i++)
		/* do nothing */;
	if (i != data.argc)
		goto out;
	for (i = 0; data.env[i] != NULL; i++)
		/* do nothing */;
	if (i != data.envc)
		goto out;

	retval = 0;
	if (executable != NULL) {
		*executable = data.executable;
		data.executable = NULL;
	}
	if (argv != NULL) {
		*argv = data.argv;
		data.argv = NULL;
	}
	if (env != NULL) {
		*env = data.env;
		data.env = NULL;
	}
	if (param != NULL)
		*param = data.param;

out:
	g_markup_parse_context_free(context);

	return retval;
}

char* serv_msg_kill_new(const char *name, int signal, long timeo)
{
	g_return_val_if_fail(name != NULL, NULL);

	return g_markup_printf_escaped("<serv_msg_kill>"
			"<name>%s</name>"
			"<signal>%d</signal>"
			"<timeout>%ld</timeout>"
			"</serv_msg_kill>", name, signal, timeo);
}

void serv_msg_kill_free(char *msg)
{
	g_free(msg);
}

struct __serv_msg_kill_parse_data
{
	char	*name;
	int	signal;
	long	timeout;
};

static void __serv_msg_kill_parse_data_free(gpointer data)
{
	struct __serv_msg_kill_parse_data *pdata = data;
	
	if (pdata->name != NULL)
		free(pdata->name);
}

static void __serv_msg_kill_start_element(GMarkupParseContext *context,
		const gchar *element_name, const gchar **attribute_names,
		const gchar **attribute_values, gpointer user_data,
		GError **error)
{
	if (strcmp(element_name, "service") == 0) {
		int i;
		const gchar *type = NULL;

		for (i = 0; attribute_names[i] != NULL; i++) {
			if (strcmp(attribute_names[i], "type") == 0) {
				type = attribute_values[i];
				break;
			}
		}
		if (type == NULL || strcmp(type, "kill") != 0)
			goto err;
	}

	return;

err:
	*error = g_error_new(G_MARKUP_ERROR,
			G_MARKUP_ERROR_INVALID_CONTENT, "Invalid content");
}

static void __serv_msg_kill_text(GMarkupParseContext *context,
		const gchar *text, gsize text_len, gpointer user_data,
		GError **error)
{
	struct __serv_msg_kill_parse_data *pdata = user_data;
	const gchar *element_name = g_markup_parse_context_get_element(context);

	if (strcmp(element_name, "name") == 0) {
		if (pdata->name != NULL)
			goto err;
		pdata->name = strdup(text);
		if (pdata->name == NULL)
			goto err;
	} else if (strcmp(element_name, "signal") == 0)
		pdata->signal = atoi(text);
	else if (strcmp(element_name, "timeout") == 0)
		pdata->timeout = atol(text);
	
	return;

err:
	*error = g_error_new(G_MARKUP_ERROR,
			G_MARKUP_ERROR_INVALID_CONTENT, "Invalid content");
}

static GMarkupParser __serv_msg_kill_parser = {
	.start_element	= __serv_msg_kill_start_element,
	.text		= __serv_msg_kill_text,
};

int serv_msg_kill_parse(char **name, int *signal, long *timeo, char *msg)
{
	GMarkupParseContext *context;
	struct __serv_msg_kill_parse_data data;

	memset(&data, 0, sizeof(data));
	context = g_markup_parse_context_new(&__serv_msg_kill_parser, 0, &data,
			__serv_msg_kill_parse_data_free);
	if (context == NULL)
		return -1;
	if (!g_markup_parse_context_parse(context, msg, strlen(msg), NULL) ||
	    !g_markup_parse_context_end_parse(context, NULL)) {
	    	g_markup_parse_context_free(context);
		return -1;
	}
	
	if (name != NULL) {
		*name = data.name;
		data.name = NULL;
	}
	if (signal != NULL)
		*signal = data.signal;
	if (timeo != NULL)
		*timeo = data.timeout;
	
	g_markup_parse_context_free(context);

	return 0;
}

/* service status message */
char* serv_msg_st_new(int code, const char *detail)
{
	return g_markup_printf_escaped("<service type=\"status\">"
			"<code>%d</code><detail>%s</detail>"
			"</service>",
			code, detail);
}

void serv_msg_st_free(char *msg)
{
	g_free(msg);
}

struct __serv_msg_st_parse_data {
	int	code;
	char	*detail;
};

static void __serv_msg_st_parse_data_free(gpointer data)
{
	struct __serv_msg_st_parse_data *pdata = data;

	if (pdata->detail != NULL)
		free(pdata->detail);
};

static void __serv_msg_st_start_element(GMarkupParseContext *context,
		const gchar *element_name, const gchar **attribute_names,
		const gchar **attribute_values, gpointer user_data,
		GError **error)
{
	if (strcmp(element_name, "service") == 0) {
		int i;
		const gchar *type = NULL;

		for (i = 0; attribute_names[i] != NULL; i++) {
			if (strcmp(attribute_names[i], "type") == 0) {
				type = attribute_values[i];
				break;
			}
		}
		if (type == NULL || strcmp(type, "status") != 0)
			goto err;
	}

	return;

err:
	*error = g_error_new(G_MARKUP_ERROR,
			G_MARKUP_ERROR_INVALID_CONTENT, "Invalid content");
}

static void __serv_msg_st_text(GMarkupParseContext *context, const gchar *text,
		gsize text_len, gpointer user_data, GError **error)
{
	struct __serv_msg_st_parse_data *pdata = user_data;
	const gchar *element_name = g_markup_parse_context_get_element(context);

	if (strcmp(element_name, "code") == 0)
		pdata->code = atoi(text);
	else if (strcmp(element_name, "detail") == 0) {
		if (pdata->detail != NULL)
			goto err;
		pdata->detail = strdup(text);
		if (pdata->detail == NULL)
			goto err;
	}
	
	return;

err:
	*error = g_error_new(G_MARKUP_ERROR,
			G_MARKUP_ERROR_INVALID_CONTENT, "Invalid content");
}

static GMarkupParser __serv_msg_st_parser = {
	.start_element	= __serv_msg_st_start_element,
	.text		= __serv_msg_st_text,
};

int serv_msg_st_parse(int *code, char **detail, char *msg)
{
	GMarkupParseContext *context;
	struct __serv_msg_st_parse_data data;

	memset(&data, 0, sizeof(data));
	context = g_markup_parse_context_new(&__serv_msg_st_parser, 0, &data,
			__serv_msg_st_parse_data_free);
	if (context == NULL)
		return -1;
	if (!g_markup_parse_context_parse(context, msg, strlen(msg), NULL) ||
	    !g_markup_parse_context_end_parse(context, NULL)) {
		g_markup_parse_context_free(context);
		return -1;
	}

	if (code != NULL)
		*code = data.code;
	if (detail != NULL) {
		*detail = data.detail;
		data.detail = NULL;
	}

	g_markup_parse_context_free(context);

	return 0;
}

#if 0
/* test routine */
extern char **environ;
int main(int argc, char *argv[])
{
	char *msg;
	struct serv_param param = {
		.mem_threshold = 1,
		.flags = 2,
		.core_dump = 4
	};
	char *executable = "xxxxx";
	int i, code = -1;
	char *detail = "OK";
	char **env = environ;

	msg = serv_msg_exec_new(executable, argv, env, &param);
	printf("%s\n", msg);
	executable = NULL;
	argc = 0;
	argv = NULL;
	memset(&param, 0, sizeof(param));
	serv_msg_exec_parse(&executable, &argv, &env, &param, msg);
	serv_msg_exec_free(msg);

	msg = serv_msg_exec_new(executable, argv, env, &param);
	free(executable);
	strv_free(argv);
	strv_free(env);
	printf("%s\n", msg);
	serv_msg_exec_free(msg);

	msg = serv_msg_st_new(code, detail);
	printf("%s\n", msg);
	code = 0;
	detail = NULL;
	serv_msg_st_parse(&code, &detail, msg);
	serv_msg_st_free(msg);

	msg = serv_msg_st_new(code, detail);
	free(detail);
	printf("%s\n", msg);
	serv_msg_st_free(msg);

	return 0;
}
#endif
