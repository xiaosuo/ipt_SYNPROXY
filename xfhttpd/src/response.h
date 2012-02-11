
#ifndef __RESPONSE_H
#define __RESPONSE_H

#include <stdint.h>
#include <time.h>

enum response_flag_t {
	RESPONSE_FLAG_HAS_LENGTH,
	RESPONSE_FLAG_HAS_RANGE,
};

struct response {
	int		flags;
	unsigned	code;
	time_t		last_mod_time;
	uint64_t	start, end, length, offset;
	const char	*mime_type;
};

#endif /* __RESPONSE_H */
