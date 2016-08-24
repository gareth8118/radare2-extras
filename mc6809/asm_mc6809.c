/* radare2 - GPL - Copyright 2016 - gde */

#include <stdio.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "mc6809.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return mc6809_disassemble(a->pc, op, buf, len);
}

RAsmPlugin r_asm_plugin_mc6809 = {
	.name = "mc6809",
	.arch = "mc6809",
	.bits = 8,
	.desc = "Motorola MC6809 disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.license = "GPL",
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mc6809,
	.version = R2_VERSION
};
#endif