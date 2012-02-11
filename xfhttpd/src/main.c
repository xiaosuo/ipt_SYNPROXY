
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "daemon.h"
#include "misc.h"
#include "config.h"
#include "request.h"
#include "mime.h"
#include "version.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int start_server(void)
{
	int fd, reuse;
	struct sockaddr_in addr;
	socklen_t len;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	reuse = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(config.option.port);
	len = sizeof(addr);
	bind(fd, (struct sockaddr*)&addr, len);
	listen(fd, 10);

	return fd;
}

void send_response(int conn_fd, struct request *req)
{
	int fd;
	char *filename;
	char buf[4096];
	int retval;

	if (req->url.path[0] == '/')
		filename = req->url.path + 1;
	else
		filename = req->url.path;
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return;
	retval = snprintf(buf, sizeof(buf), "HTTP/%hu.%hu 200 OK\r\n"
			"Server: " SERVER "\r\n"
			"Connection: close\r\n"
			"Content-Type: %s\r\n\r\n",
			HTTP_MAJOR(req->version), HTTP_MINOR(req->version),
			get_mime_from_ext(filename));
	write(1, buf, retval);
	write(conn_fd, buf, retval);
	retval = read(fd, buf, sizeof(buf));
	if (retval < 0) {
		close(fd);
		return;
	}
	write(conn_fd, buf, retval);
	close(conn_fd);
}

int main(int argc, char *argv[])
{
	int serv_fd, conn_fd, retval;
	char buf[1024];

	parse_args(argc, argv);

	assert(init_mime("mime.conf") == 0);

	if (!config.option.debug) {
		if (daemonize("xfhttpd") != 0)
			die("can't become a daemon");
	} else {
		log_debug("debug mode");
	}

	serv_fd = start_server();

loop:
	conn_fd = accept(serv_fd, NULL, NULL);
	retval = read(conn_fd, buf, sizeof(buf));
	write(1, buf, retval);

	struct request_parse_context ctx;
	struct request request;

	request_parse_context_init(&ctx);
	memset(&request, 0, sizeof(request));

	assert(parse_request(buf, retval, &ctx, &request) == REQUEST_PARSE_RETVAL_OK);
	printf("cmd: %s\n", http_cmd_str[request.cmd]);
	printf("host: %s\n", request.host);
	printf("path: %s\n", request.url.path);
	printf("query: %s\n", request.url.query ? : "NULL");
	printf("proto: %d.%d\n", HTTP_MAJOR(request.version),
	       HTTP_MINOR(request.version));
	send_response(conn_fd, &request);
	close(conn_fd);
	goto loop;
	
	return EXIT_SUCCESS;
}
