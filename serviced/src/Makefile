
CFLAGS := `pkg-config --cflags glib-2.0` -fPIC -Wall -I.
LDFLAGS := `pkg-config --libs glib-2.0` -lpthread -lrt -L.
TARGET := serviced libserviced.so servctl

.PHONY: clean

all: $(TARGET)

serviced: main.o servmsg.o misc.o
	$(CC) -o $@ $^ $(LDFLAGS)

libserviced.so: serviced.o misc.o servmsg.o ld.script
	$(CC) -o $@ $^ $(LDFLAGS) -shared

servctl: servctl.o servmsg.o misc.o
	$(CC) -o $@ $^ $(LDFLAGS) -lserviced

clean:
	rm -f $(TARGET) *.o

install: all
