// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>

#include "pathname.h"

#define WILDCARD_STR "*"
#define WILDCARD WILDCARD_STR[0]

int ipe_validate_pathname_pattern(const char *pattern)
{
	char *last_wildcard, *first_wildcard;
	/* ensure a wildcard is postfix, if one is present */
	last_wildcard = strrchr(pattern, WILDCARD);
	if (last_wildcard) {
		first_wildcard = strchr(pattern, WILDCARD);
		if (last_wildcard != first_wildcard)
			return -EBADMSG;
		++last_wildcard;
		if (*last_wildcard != '\0')
			return -EBADMSG;
	}

	return 0;
}

bool ipe_match_pathname(const char *pattern, const char *path)
{
	size_t len;
	const char *match;

	match = strstr(pattern, WILDCARD_STR);
	/* no wildcard */
	if (!match)
		len = strlen(pattern);
	else
		len = match - pattern;

	return !strncmp(pattern, path, len);
}
