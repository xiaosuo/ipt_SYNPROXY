
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "request.h"
#include "misc.h"

static char __xdigit2char(char ch)
{
	switch (ch) {
	case '0'...'9':
		return ch - '0';
	case 'A'...'F':
		return ch - 'A' + 10;
	case 'a'...'f':
		return ch - 'a' + 10;
	default:
		return 0;
	}
}

static char xdigit2char(char *ptr)
{
	return (__xdigit2char(ptr[0]) << 4) | __xdigit2char(ptr[1]);
}

/* split url into path and query, unescape the %XX sequence, but keep query
 * string escaped for CGI, at the same time, trip "/../", "/./" and "//"
 * sequences in path to make path clear and safe. */
static void parse_url(char *ptr, struct url_parse_context *ctx, struct url *url)
{
	int old_out_offset = ctx->out_offset;
	char ch;

	/* RFC 3986: 3.4
	 * query       = *( pchar / "/" / "?" )
	 * The characters slash ("/") and question mark ("?")
	 * may represent data within the query component. */
	if (*ptr == '?' && ctx->state < URL_PARSE_STATE_QUERYING_INIT) {
		*ptr = '\0';
		switch (ctx->state) {
		case URL_PARSE_STATE_INIT:
		/* for example: http://foobar?query */
			url->path = ptr;
			break;
		case URL_PARSE_STATE_PERCENT_XDIGIT:
			if (ctx->in_offset != ctx->out_offset)
				url->path[ctx->out_offset++] = *(ptr - 2);
			else
				ctx->out_offset++;
			ctx->in_offset++;
		case URL_PARSE_STATE_PERCENT:
			if (ctx->in_offset != ctx->out_offset)
				url->path[ctx->out_offset++] = *(ptr - 1);
			else
				ctx->out_offset++;
			ctx->in_offset++;
		case URL_PARSE_STATE_RUNNING:
			if (ctx->in_offset != ctx->out_offset)
				url->path[ctx->out_offset++] = *ptr;
			else
				ctx->out_offset++;
			ctx->in_offset++;
			break;
		default:
			/* just for syntax completion */
			break;
		}
		ctx->state = URL_PARSE_STATE_QUERYING_INIT;

		return;
	}

	switch (ctx->state) {
	case URL_PARSE_STATE_INIT:
		url->path = ptr;
		if (*ptr == '%') {
			ctx->state = URL_PARSE_STATE_PERCENT;
		} else {
			ctx->state = URL_PARSE_STATE_RUNNING;
			ctx->in_offset++;
			ctx->out_offset++;
		}
		break;
	case URL_PARSE_STATE_RUNNING:
		if (*ptr == '%') {
			ctx->state = URL_PARSE_STATE_PERCENT;
		} else {
			if (ctx->in_offset != ctx->out_offset)
				url->path[ctx->out_offset++] = *ptr;
			else
				ctx->out_offset++;
			ctx->in_offset++;
		}
		break;
	case URL_PARSE_STATE_PERCENT:
		if (isxdigit(*ptr)) {
			ctx->state = URL_PARSE_STATE_PERCENT_XDIGIT;
		} else {
			ctx->state = URL_PARSE_STATE_RUNNING;
			if (ctx->in_offset != ctx->out_offset) {
				url->path[ctx->out_offset++] = *(ptr - 1);
				url->path[ctx->out_offset++] = *ptr;
			} else {
				ctx->out_offset += 2;
			}
			ctx->in_offset += 2;
		}
		break;
	case URL_PARSE_STATE_PERCENT_XDIGIT:
		ctx->state = URL_PARSE_STATE_RUNNING;
		if (isxdigit(*ptr)) {
			url->path[ctx->out_offset++] = xdigit2char(ptr - 1);
			ctx->in_offset += 3;
		} else {
			if (ctx->in_offset != ctx->out_offset) {
				url->path[ctx->out_offset++] = *(ptr - 2);
				url->path[ctx->out_offset++] = *(ptr - 1);
				url->path[ctx->out_offset++] = *ptr;
			} else {
				ctx->out_offset += 3;
			}
			ctx->in_offset += 3;
		}
		break;
	case URL_PARSE_STATE_QUERYING_INIT:
		ctx->state = URL_PARSE_STATE_QUERYING;
		url->query = ptr;
		break;
	case URL_PARSE_STATE_QUERYING:
		/* keep escaped */
		break;
	default:
		die("Invalid URL_PARSE_STATE: %d", ctx->state);
	}

	if (ctx->out_offset == old_out_offset)
		return;
	else if (ctx->out_offset - old_out_offset > 1) {
		if (ctx->vstate != URL_VALID_STATE_NORMAL)
			ctx->vstate = URL_VALID_STATE_NORMAL;
		return;
	}

	ch = url->path[old_out_offset];

	/* GET .* HTTP/1.1 */
	if (old_out_offset == 0 && ch == '.') {
		ctx->vstate = URL_VALID_STATE_SLASH_DOT;
		return;
	}

	switch (ctx->vstate) {
	case URL_VALID_STATE_NORMAL:
		if (ch == '/')
			ctx->vstate = URL_VALID_STATE_SLASH;
		break;
	case URL_VALID_STATE_SLASH:
		if (ch == '.') {
			/* /foo/bar.* */
			ctx->vstate = URL_VALID_STATE_SLASH_DOT;
		} else if (ch == '/') {
			/* /foo//bar */
			ctx->vstate = URL_VALID_STATE_NORMAL;
			ctx->out_offset -= 1;
		} else {
			ctx->vstate = URL_VALID_STATE_NORMAL;
		}
		break;
	case URL_VALID_STATE_SLASH_DOT:
		if (ch == '.') {
			/* /foo/bar/..* */
			ctx->vstate = URL_VALID_STATE_SLASH_DOT_DOT;
		} else if (ch == '/') {
			/* /foo/bar/./ */
			ctx->vstate = URL_VALID_STATE_NORMAL;
			ctx->out_offset -= 2;
		} else if (ch == '\0') {
			/* /foo/bar/. */
			ctx->vstate = URL_VALID_STATE_NORMAL;
			ctx->out_offset -= 2;
			url->path[ctx->out_offset] = '\0';
		} else {
			ctx->vstate = URL_VALID_STATE_NORMAL;
		}
		break;
	case URL_VALID_STATE_SLASH_DOT_DOT:
		ctx->vstate = URL_VALID_STATE_NORMAL;
		if (ch == '/') {
			ctx->out_offset -= 3;
			if (ctx->out_offset > 1) {
				ptr = memrchr(url->path, '/',
					      ctx->out_offset - 1);
				if (ptr != NULL) {
					/* /foo/../ */
					ctx->out_offset = ptr - url->path + 1;
				} else {
					/* foo/../ */
					ctx->out_offset = 0;
				}
			}
		} else if (ch == '\0') {
			ctx->out_offset -= 3;
			if (ctx->out_offset > 1) {
				ptr = memrchr(url->path, '/',
					      ctx->out_offset - 1);
				if (ptr != NULL) {
					/* /foo/.. */
					ctx->out_offset = ptr - url->path + 1;
				} else {
					/* foo/.. */
					ctx->out_offset = 0;
				}
			}
			url->path[ctx->out_offset] = '\0';
		}
		break;
	default:
		die("Invalid: URL_VALID_STATE: %d", ctx->vstate);
	}
}

const char *http_cmd_str[] = {
	[HTTP_CMD_UNKNOWN]	= "UNKNOWN",
	[HTTP_CMD_GET]		= "GET",
	[HTTP_CMD_POST]		= "POST",
	[HTTP_CMD_PUT]		= "PUT",
	[HTTP_CMD_HEAD]		= "HEAD",
};

/* field-name IS case-insensitive, and value maybe multi-line. */
static void extract_header(struct request *request, const char *name,
		int namelen, const char *value)
{
	switch (namelen) {
	case 4:
		/* host's value SHOULD be case-insensitive */
		if (strcasecmp(name, "Host") == 0)
			request->host = value;
		break;
	default:
		break;
	}
}

static enum http_cmd extract_cmd(const char *cmd, int namelen)
{
	switch (namelen) {
	case 3:
		switch (cmd[0]) {
		case 'G':
			return (cmd[1] == 'E' && cmd[2] == 'T') ?
				HTTP_CMD_GET : HTTP_CMD_UNKNOWN;
		case 'P':
			return (cmd[1] == 'U' && cmd[2] == 'T') ?
				HTTP_CMD_PUT : HTTP_CMD_UNKNOWN;
		default:
			return HTTP_CMD_UNKNOWN;
		}
	case 4:
		switch (cmd[0]) {
		case 'H':
			return (cmd[1] == 'E' && cmd[2] == 'A' &&
				cmd[3] == 'D') ? HTTP_CMD_HEAD :
				HTTP_CMD_UNKNOWN;
		case 'P':
			return (cmd[1] == 'O' && cmd[2] == 'S' &&
				cmd[3] == 'T') ? HTTP_CMD_POST :
				HTTP_CMD_UNKNOWN;
		default:
			return HTTP_CMD_UNKNOWN;
		}
	case 5:
		if (cmd[0] == 'T' && cmd[1] == 'R' && cmd[2] == 'A' &&
		    cmd[3] == 'C' && cmd[4] == 'E')
			return HTTP_CMD_TRACE;
		else
			return HTTP_CMD_UNKNOWN;
	case 6:
		if (cmd[0] == 'D' && cmd[1] == 'E' && cmd[2] == 'L' &&
		    cmd[3] == 'E' && cmd[4] == 'T' && cmd[5] == 'E')
			return HTTP_CMD_DELETE;
		else
			return HTTP_CMD_UNKNOWN;
	case 7:
		switch (cmd[0]) {
		case 'O':
			if (cmd[1] == 'P' && cmd[2] == 'T' && cmd[3] == 'I' &&
			    cmd[4] == 'O' && cmd[5] == 'N' && cmd[6] == 'S')
				return HTTP_CMD_OPTIONS;
			else
				return HTTP_CMD_UNKNOWN;
		case 'C':
			if (cmd[1] == 'O' && cmd[2] == 'N' && cmd[3] == 'N' &&
			    cmd[4] == 'E' && cmd[5] == 'C' && cmd[6] == 'T')
				return HTTP_CMD_CONNECT;
			else
				return HTTP_CMD_UNKNOWN;
		default:
			return HTTP_CMD_UNKNOWN;
		}
	default:
		return HTTP_CMD_UNKNOWN;
	}
}

static int extract_version(char *proto)
{
	unsigned short major, minor;
	char http[5];

	/* avoid sscanf in the common case */
	if (proto[0] == 'H' && proto[1] == 'T' && proto[2] == 'T' &&
	    proto[3] == 'P' && proto[4] == '/' && isdigit(proto[5]) &&
	    proto[6] == '.' && isdigit(proto[7]) && proto[8] == '\0')
		return HTTP_VERSION(proto[5] - '0', proto[7] - '0');
	/* XXX: HTTP must be in uppercase, but apache treats it in
	 * case-insensitive manner, so do I. :) */
	else if (sscanf(proto,  "%4s/%hu.%hu", http, &major, &minor) == 3 &&
		   strcasecmp(http, "http") == 0)
			return HTTP_VERSION(major, minor);

	return 0;
}

/* parse the whole request: request lines and headers, into structure request,
 * but leave the body data ether in socket buffer or local buffer for future
 * optimization.
 * XXX: all the dynamic variables use the space in buf, so no free is needed,
 * and the variabe buf maybe changed. */
enum request_parse_retval parse_request(char *buf, int len,
		struct request_parse_context *ctx, struct request *request)
{
	char *ptr, *end, *tmp;

	end = buf + len;
	for (ptr = buf + ctx->offset; ptr < end; ptr++) {
		switch (ctx->state) {
		case REQUEST_PARSE_STATE_INIT:
			ctx->cmd = ptr;
			ctx->state = REQUEST_PARSE_STATE_COMMAND_BEGIN;
			break;
		case REQUEST_PARSE_STATE_COMMAND_BEGIN:
			tmp = memchr(ptr, ' ', end - ptr);
			if (tmp != NULL) {
				ptr = tmp;
				*ptr = '\0';
				request->cmd = extract_cmd(ctx->cmd,
							   ptr - ctx->cmd);
				if (request->cmd == HTTP_CMD_UNKNOWN)
					return REQUEST_PARSE_RETVAL_FAILURE;
				ctx->state = REQUEST_PARSE_STATE_COMMAND_END;
			} else {
				ptr = end - 1;
			}
			break;
		case REQUEST_PARSE_STATE_COMMAND_END:
			if (*ptr != ' ') {
				ctx->state = REQUEST_PARSE_STATE_URL_BEGIN;
				memset(&ctx->url, 0, sizeof(ctx->url));
				parse_url(ptr, &ctx->url, &request->url);
			}
			break;
		case REQUEST_PARSE_STATE_URL_BEGIN:
			if (*ptr == ' ') {
				*ptr = '\0';
				ctx->state = REQUEST_PARSE_STATE_URL_END;
			}
			parse_url(ptr, &ctx->url, &request->url);
			break;
		case REQUEST_PARSE_STATE_URL_END:
			if (*ptr != ' ') {
				ctx->proto = ptr;
				ctx->state = REQUEST_PARSE_STATE_PROTO_BEGIN;
			}
			break;
		case REQUEST_PARSE_STATE_PROTO_BEGIN:
			tmp = memchr(ptr, '\r', end - ptr);
			if (tmp != NULL) {
				ptr = tmp;
				*ptr = '\0';
				request->version = extract_version(ctx->proto);
				if (request->version < HTTP_VERSION(1, 0))
					return REQUEST_PARSE_RETVAL_FAILURE;
				ctx->state = REQUEST_PARSE_STATE_PROTO_END;
			} else {
				ptr = end - 1;
			}
			break;
		case REQUEST_PARSE_STATE_PROTO_END:
			if (*ptr != '\n')
				return REQUEST_PARSE_RETVAL_FAILURE;
			ctx->state = REQUEST_PARSE_STATE_RN;
			break;
		case REQUEST_PARSE_STATE_RN:
			if (*ptr == '\r') {
				ctx->state = REQUEST_PARSE_STATE_RNR;
			} else {
				ctx->name = ptr;
				ctx->state = REQUEST_PARSE_STATE_NAME_BEGIN;
			}
			break;
		case REQUEST_PARSE_STATE_RNR:
			if (*ptr != '\n')
				return REQUEST_PARSE_RETVAL_FAILURE;
			ctx->state = REQUEST_PARSE_STATE_RNRN;
			break;
		case REQUEST_PARSE_STATE_RNRN:
			goto done;
			break;
		case REQUEST_PARSE_STATE_NAME_BEGIN:
			tmp = memchr(ptr, ':', end - ptr);
			if (tmp != NULL) {
				ptr = tmp;
				*ptr = '\0';
				ctx->namelen = ptr - ctx->name;
				ctx->state = REQUEST_PARSE_STATE_NAME_END;
			} else {
				ptr = end - 1;
			}
			break;
		case REQUEST_PARSE_STATE_NAME_END:
			if (*ptr == '\r') {
				ctx->state = REQUEST_PARSE_STATE_NAME_END_R;
			} else if (*ptr != ' ' && *ptr != '\t') {
				ctx->value = ptr;
				ctx->state = REQUEST_PARSE_STATE_VALUE_BEGIN;
			}
			break;
		case REQUEST_PARSE_STATE_NAME_END_R:
			if (*ptr == '\n') {
				ctx->state = REQUEST_PARSE_STATE_NAME_END_RN;
			} else {
				ctx->value = ptr - 1;
				ctx->state = REQUEST_PARSE_STATE_VALUE_BEGIN;
			}
			break;
		case REQUEST_PARSE_STATE_NAME_END_RN:
			if (*ptr == ' ' || *ptr == '\t') {
				ctx->state = REQUEST_PARSE_STATE_NAME_END;
			} else {
				/* empty value */
				ctx->value = ptr - 1;
				*(ctx->value) = '\0';
				extract_header(request, ctx->name,
					       ctx->namelen, ctx->value);
				ctx->name = ptr;
				ctx->state = REQUEST_PARSE_STATE_NAME_BEGIN;
			}
			break;
		case REQUEST_PARSE_STATE_VALUE_BEGIN:
			tmp = memchr(ptr, '\r', end - ptr);
			if (tmp != NULL) {
				ptr = tmp;
				ctx->state = REQUEST_PARSE_STATE_VALUE_BEGIN_R;
			} else {
				ptr = end - 1;
			}
			break;
		case REQUEST_PARSE_STATE_VALUE_BEGIN_R:
			if (*ptr == '\n')
				ctx->state = REQUEST_PARSE_STATE_VALUE_BEGIN_RN;
			else
				ctx->state = REQUEST_PARSE_STATE_VALUE_BEGIN;
			break;
		case REQUEST_PARSE_STATE_VALUE_BEGIN_RN:
			if (*ptr == ' ' || *ptr == '\t') {
				ctx->state = REQUEST_PARSE_STATE_VALUE_BEGIN;
			} else {
				*(ptr - 2) = '\0';
				extract_header(request, ctx->name,
					       ctx->namelen, ctx->value);
				if (*ptr == '\r') {
					ctx->state = REQUEST_PARSE_STATE_RNR;
				} else {
					ctx->name = ptr;
					ctx->state = REQUEST_PARSE_STATE_NAME_BEGIN;
				}
			}
			break;
		default:
			die("Invalid REQUEST_PARSE_STATE: %d", ctx->state);
			break;
		}
	}

done:
	ctx->offset = ptr - buf;

	return ctx->state == REQUEST_PARSE_STATE_RNRN ?
	       REQUEST_PARSE_RETVAL_OK : REQUEST_PARSE_RETVAL_CONTINUE;
}
