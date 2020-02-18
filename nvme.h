/*
 * Definitions for the NVM Express interface
 * Copyright (c) 2011-2014, Intel Corporation.  *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _NVME_H
#define _NVME_H

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <endian.h>

#include "plugin.h"
#include "util/argconfig.h"
#include "util/user-types.h"

#include <libnvme.h>

#define JSON 0
#define NORMAL NVME_JSON_TABULAR
#define BINARY NVME_JSON_BINARY
#define VERBOSE (NVME_JSON_DECODE_COMPLEX|NVME_JSON_HUMAN)

void register_extension(struct plugin *plugin);
int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *clo);

extern const char *devicename;

void nvme_show_status(const char *prefix, int status);
int validate_output_format(char *format);
int __id_ctrl(int argc, char **argv, struct command *cmd,
	struct plugin *plugin, void (*vs)(__u8 *vs, struct json_object *root));

#endif /* _NVME_H */
