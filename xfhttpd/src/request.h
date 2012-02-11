
#ifndef __REQUEST_H
#define __REQUEST_H

#include <string.h>

struct url {
	char *path;	/* unescapted version */
	char *query;	/* escapted version */
};

enum url_parse_state {
	URL_PARSE_STATE_INIT,
	URL_PARSE_STATE_RUNNING,
	URL_PARSE_STATE_PERCENT,
	URL_PARSE_STATE_PERCENT_XDIGIT,
	URL_PARSE_STATE_QUERYING_INIT,
	URL_PARSE_STATE_QUERYING,
};

enum url_valid_state {
	URL_VALID_STATE_NORMAL,
	URL_VALID_STATE_SLASH,
	URL_VALID_STATE_SLASH_DOT,
	URL_VALID_STATE_SLASH_DOT_DOT,
};

struct url_parse_context {
	enum url_valid_state	vstate;
	enum url_parse_state	state;
	int			in_offset, out_offset;
};

enum http_cmd {
	HTTP_CMD_UNKNOWN,
	HTTP_CMD_OPTIONS,
	HTTP_CMD_GET,
	HTTP_CMD_HEAD,
	HTTP_CMD_POST,
	HTTP_CMD_PUT,
	HTTP_CMD_DELETE,
	HTTP_CMD_TRACE,
	HTTP_CMD_CONNECT,
};

extern const char *http_cmd_str[];

#define HTTP_VERSION(major, minor) (((major) << 16) | (minor))
#define HTTP_MAJOR(version) ((version) >> 16)
#define HTTP_MINOR(version) ((version) & 0xff)

struct request {
	enum http_cmd	cmd;
	int		version;
	struct url	url;
	const char	*host;
};

enum request_parse_state {
	REQUEST_PARSE_STATE_INIT,
	REQUEST_PARSE_STATE_COMMAND_BEGIN,
	REQUEST_PARSE_STATE_COMMAND_END,
	REQUEST_PARSE_STATE_URL_BEGIN,
	REQUEST_PARSE_STATE_URL_END,
	REQUEST_PARSE_STATE_PROTO_BEGIN,
	REQUEST_PARSE_STATE_PROTO_END,
	REQUEST_PARSE_STATE_RN,
	REQUEST_PARSE_STATE_NAME_BEGIN,
	REQUEST_PARSE_STATE_NAME_END,
	REQUEST_PARSE_STATE_NAME_END_R,
	REQUEST_PARSE_STATE_NAME_END_RN,
	REQUEST_PARSE_STATE_VALUE_BEGIN,
	REQUEST_PARSE_STATE_VALUE_BEGIN_R,
	REQUEST_PARSE_STATE_VALUE_BEGIN_RN,
	REQUEST_PARSE_STATE_RNR,
	REQUEST_PARSE_STATE_RNRN,
};

enum request_parse_retval {
	REQUEST_PARSE_RETVAL_OK,
	REQUEST_PARSE_RETVAL_CONTINUE,
	REQUEST_PARSE_RETVAL_FAILURE,
};

struct request_parse_context {
	enum request_parse_state	state;
	int				offset;
	union {
		struct {
			char		*name;
			int		namelen;
		};
		struct {
			char		*cmd;
		};
		struct url_parse_context	url;
		struct {
			char		*proto;
		};
	};
	char				*value;
};

static inline void request_parse_context_init(struct request_parse_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

enum request_parse_retval parse_request(char *buf, int len,
		struct request_parse_context *ctx, struct request *request);

#endif /* __REQUEST_H */
