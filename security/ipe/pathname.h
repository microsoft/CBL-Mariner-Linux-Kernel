/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef _IPE_PATHNAME_H
#define _IPE_PATHNAME_H

int ipe_validate_pathname_pattern(const char *rule_pattern);
bool ipe_match_pathname(const char *pattern, const char *path);

#endif /* _IPE_PATHNAME_H */
