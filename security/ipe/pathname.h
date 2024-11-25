/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef _IPE_PATHNAME_H
#define _IPE_PATHNAME_H

#ifdef CONFIG_IPE_PROP_INTENDED_PATHNAME
int ipe_validate_pathname_pattern(const char *rule_pattern);
bool ipe_match_pathname(const char *pattern, const char *path);
#else
static inline int ipe_validate_pathname_pattern(const char *rule_pattern)
{
	return 0;
}
static inline bool ipe_match_pathname(const char *pattern, const char *path)
{
	return false;
}
#endif /* CONFIG_IPE_PROP_INTENDED_PATHNAME */

#endif /* _IPE_PATHNAME_H */
