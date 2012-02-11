
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mime.h"

/* case-insensitive chars 'a' - 'z', number '0' - '9', and '.' */
#define MIME_EXT_ALPHABET_SIZE 37

struct mime_node {
	struct mime_node	*next[MIME_EXT_ALPHABET_SIZE];
	const char		*type;
};

static struct mime_node *mime_root = NULL;

static inline int mime_encode(char ch)
{
	switch (ch) {
	case 'a'...'z':
		return ch - 'a';
	case 'A'...'Z':
		return ch - 'A';
	case '0'...'9':
		return  ch - '0' + 26;
	case '.':
		return 36;
	default:
		return -1;
	}
}

static int insert_mime(const char *ext, const char *type)
{
	const char *ptr;
	int ch;
	struct mime_node *node;

	if (mime_root == NULL) {
		mime_root = calloc(1, sizeof(*node));
		if (mime_root == NULL)
			return -1;
	}
	node = mime_root;
	for (ptr = ext + strlen(ext) - 1; ptr >= ext; ptr--) {
		ch = mime_encode(*ptr);
		if (ch < 0)
			return -1;
		if (node->next[ch] == NULL) {
			node->next[ch] = calloc(1, sizeof(*node));
			if (node->next[ch] == NULL)
				return -1;
		}
		node = node->next[ch];
	}
	if (node->type != NULL)
		return -1;
	node->type = strdup(type);
	if (node->type == NULL)
		return -1;

	return 0;
}

int init_mime(const char *filename)
{
	FILE *fp;
	char buf[256];
	int retval, has_default;
	char *ptr, *ext, *type;

	has_default = 0;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/* strip buf */
		retval = strlen(buf);
		if (buf[retval - 1] == '\n')
			buf[--retval] = '\0';
		else if (!feof(fp))
			break;
		if (retval > 0 && buf[retval - 1] == '\r')
			buf[--retval] = '\0';

		ext = buf + strspn(buf, " \t");
		/* comment or empty line */
		if (*ext == '#' || *ext == '\0')
			continue;
		type = ext + strcspn(ext, " \t");
		if (*type == '\0') {
			/* only has ext ? */
			retval = -1;
			break;
		}
		*type++ = '\0';
		type += strspn(type, " \t");
		if (*type == '\0' || *type == '#') {
			/* only has ext ? */
			retval = -1;
			break;
		}
		ptr = type + strcspn(type, " \t");
		if (*ptr != '\0') {
			*ptr++ = '\0';
			ptr += strspn(ptr, " \t");
			if (*ptr != '\0' && *ptr != '#') {
				retval = -1;
				break;
			}
		}
		if (strcmp(ext, "*") == 0) {
			ext = "";
			has_default = 1;
		}
		if (insert_mime(ext, type) < 0)
			return -1;
	}

	if (!feof(fp))
		retval = -1;
	else if (!has_default)
		retval = insert_mime("", "application/octet-stream");
	fclose(fp);

	return retval < 0 ? retval : 0;
}

const char *get_mime_from_ext(const char *filename)
{
	int ch;
	const char *ptr, *type;
	struct mime_node *node;

	node = mime_root;
	if (node == NULL)
		return NULL;
	type = node->type;
	for (ptr = filename + strlen(filename) - 1; ptr >= filename; ptr--) {
		ch = mime_encode(*ptr);
		if (ch < 0)
			return NULL;
		if (node->next[ch] == NULL)
			break;
		node = node->next[ch];
		if (node->type != NULL)
			type = node->type;
	}

	return type;
}

#if 0
#include <assert.h>

int main(int argc, char *argv[])
{
	assert(init_mime("mime.conf") == 0);
	printf("%s\n", get_mime_from_ext(argv[1]));

	return 0;
}
#endif
