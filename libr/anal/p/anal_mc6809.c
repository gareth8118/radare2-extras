/* radare2 - GPL - Copyright 2016 - gde */

#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

RAnalPlugin r_anal_plugin_mc6809 = {
	.name = "mc6809",
	.arch = "mc6809",
	.license = "GPL",
	.arch = "mc6809",
	.bits = 8,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mc6809,
	.version = R2_VERSION,
};
#endif
