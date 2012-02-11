
CFLAGS += -Wall -D_GNU_SOURCE
LDFLAGS += -lpthread -lrt

all: xfhttpd

xfhttpd: main.o daemon.o misc.o log.o config.o mime.o request.o response.o \
	 worker_pool.o workqueue.o
	$(CC) ${LDFLAGS} -o $@ $^

clean:
	$(RM) xfhttpd *.o
