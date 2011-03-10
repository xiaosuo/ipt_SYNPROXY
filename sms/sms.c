
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef NDEBUG
#define pr_dbg(fmt, args...) \
do { \
	printf(fmt, ##args); \
	fflush(stdout); \
} while (0)
#else
#define pr_dbg(fmt, args...) do {} while (0)
#endif

static int write_all3(int fd, const char *str, int len)
{
	int retval;

	while (len > 0) {
		retval = write(fd, str, len);
		if (retval < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		str += retval;
		len -= retval;
	}

	return 0;
}

static int write_all(int fd, const char *str)
{
	return write_all3(fd, str, strlen(str));
}

static int at_write(int fd, const char *cmd)
{
	pr_dbg("\x1b\[1;34m<<< AT%s\x1b\[0m\r\n", cmd);
	if (write_all(fd, "AT") < 0)
		return -1;
	if (write_all(fd, cmd) < 0)
		return -1;
	return write_all(fd, "\r");
}

static int read_line(int fd, char *buf, int size)
{
	static char ibuf[256];
	static int ilen;
	int i;
	char *obuf = buf;

	while (1) {
		if (ilen <= 0) {
			while (1) {
				ilen = read(fd, ibuf, sizeof(ibuf));
				if (ilen < 0) {
					if (errno == EINTR)
						continue;
					return -1;
				} else if (ilen == 0) {
					return -1; /* XXX: EOF ?? */
				}
				break;
			}
		}

		for (i = 0; i < ilen; i++) {
			if (size-- < 2)
				return -1;
			*buf = ibuf[i];
			if (*buf++ == '\n') {
				*buf = '\0';
				i++;
				if (i < ilen)
					memmove(&ibuf[0], &ibuf[i], ilen - i);
				ilen = ilen - i;
				return 0;
			}
		}

		/* some commands need more parameters, such as +CMGS */
		if (buf - obuf == 2 && obuf[0] == '>' && obuf[1] == ' ') {
			if (size < 1)
				return -1;
			*buf = '\0';
			ilen = 0;
			return 1;
		}

		ilen = 0;
	}
}

static int at_wait(int fd, const char *expect)
{
	char buf[4096];
	int retval;

	while (1) {
		retval = read_line(fd, buf, sizeof(buf));
		if (retval < 0)
			return -1;
		pr_dbg("\x1b\[1;32m>>> %s\x1b[0m", buf);
		if (retval == 1)
			return 1;
		if (strcmp(buf, "OK\r\n") == 0) {
			if (expect)
				return -1;
			else
				break;
		} else if (strcmp(buf, "ERROR\r\n") == 0) {
			return -1;
		} else if (expect && strstr(buf, expect)) {
			expect = NULL;
		} else if (strncmp(buf, "+CMS ERROR", 10) == 0) {
			return -1;
		}
	}

	return 0;
}

static int at_cmd(int fd, const char *expect, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int retval;

	va_start(ap, fmt);
	retval = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (retval < 0 || retval >= sizeof(buf))
		return -1;

	if (at_write(fd, buf))
		return -1;

	return at_wait(fd, expect);
}

/* pack/unpack GSM 7-bit characters */

static inline int sms_pack_len(int len)
{
	return (len / 8 * 7 + len % 8) * 2;
}

static inline void bin2hex(unsigned char *ret, unsigned char ch)
{
	static const unsigned char *__hex = (unsigned char *)"0123456789ABCDEF";

	ret[0] = __hex[ch >> 4];
	ret[1] = __hex[ch & 0xf];
}

static void sms_pack(unsigned char *nbuf, const unsigned char *buf, int len)
{
	int i, off;
	unsigned char ch = 0;

	for (i = 0; i < len; ++i) {
		off = i % 8;
		if (off != 0) {
			ch |= buf[i] << (8 - off);
			bin2hex(nbuf, ch);
			nbuf += 2;
			ch = 0;
		}
		if (off != 7) {
			ch = buf[i] >> off;
			if (i == len - 1) {
				bin2hex(nbuf, ch);
				nbuf += 2;
			}
		}
	}
}

static unsigned char __hex2bin(unsigned char ch)
{
	switch (ch) {
	case '0'...'9':
		return ch - '0';
	case 'a'...'f':
		return ch + 10 - 'a';
	case 'A'...'F':
		return ch + 10 - 'A';
	default:
		return 0;
	}
}

static inline unsigned char hex2bin(const unsigned char *buf)
{
	return (__hex2bin(buf[0]) << 4) + __hex2bin(buf[1]);
}

static void sms_unpack(unsigned char *nbuf, const unsigned char *buf,
		       int newlen)
{
	int i, off;
	unsigned char ch = 0;

	for (i = 0; i < newlen; ++i) {
		off = i % 8;
		if (off != 0) {
			ch = hex2bin(buf);
			buf += 2;
			nbuf[i] = ch >> (8 - off);
		}
		if (off != 7) {
			ch = hex2bin(buf);
			nbuf[i] |= (ch << off) & 0x7f;
		}
	}
}

static void sms_num_enc(char *buf, const char *num, int len)
{
	int i;

	for (i = 1; i < len; i += 2) {
		buf[i] = num[i - 1];
		buf[i - 1] = num[i];
	}
	buf[len] = num[len - 1];
	buf[len - 1] = 'F';
}

static int sms_send(int fd, const char *smsc, const char *num, const char *msg)
{
	char *buf;
	int num_len, retval, tpdu_len, msg_len;

	num_len = strlen(num);
	msg_len = strlen(msg);
	tpdu_len = 15 + num_len + sms_pack_len(msg_len);

	if (at_cmd(fd, NULL, "+CMGS=%d", tpdu_len / 2) != 1)
		return -1;

	/* The SMSC Part */
	if (smsc) {
		int len;

		len = strlen(smsc);
		buf = malloc(len + 6);
		if (buf == NULL)
			return -1;
		sprintf(buf, "%02hhX91", (len + 3) / 2);
		sms_num_enc(buf + 4, smsc, len);
		buf[len + 5] = '\0';
		pr_dbg("\x1b\[1;34m%s\x1b\[0m", buf);
		retval = write_all3(fd, buf, 5 + len);
		free(buf);
		if (retval < 0)
			return -1;
	} else {
		/* Use the SMSC specified by AT command +CSCA */
		pr_dbg("\x1b\[1;34m00\x1b[0m");
		if (write_all3(fd, "00", 2))
			return -1;
	}

	/* The TPDU Part */
	buf = malloc(tpdu_len + 1);
	if (buf == NULL)
		return -1;
	sprintf(buf, "0100%02hhX91", num_len);
	sms_num_enc(buf + 8, num, num_len);
	sprintf(buf + 9 + num_len, "0000%02hhX", msg_len);
	sms_pack((unsigned char *)buf + 15 + num_len,
		 (unsigned char *)msg, msg_len);
	buf[tpdu_len] = '\0';
	pr_dbg("\x1b\[1;34m%s\n\x1b\[0m", buf);
	retval = write_all3(fd, buf, tpdu_len);
	free(buf);
	if (retval < 0)
		return -1;

	if (write_all3(fd, "\032", 1))
		return -1;

	return at_wait(fd, NULL);
}

int main(int argc, char *argv[])
{
	int fd;
	const char *smsc = NULL;

	if (argc < 4 || argc > 5) {
		fprintf(stderr, "Usage: %s [SMSC] tty dest_num msg\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 5) {
		smsc = argv[1];
		argv++;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Can't open %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	return sms_send(fd, smsc, argv[2], argv[3]);
}
