
#ifndef __MISC_H
#define __MISC_H

void __die(const char *fmt, ...);

#define die(fmt, args...) \
	__die("[%s:%d]%s: " fmt, __FILE__, __LINE__, __FUNCTION__, ##args)

#endif /* __MISC_H */
