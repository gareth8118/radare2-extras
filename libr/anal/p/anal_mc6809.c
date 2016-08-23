/* radare2 - GPL - Copyright 2016 - gde */

#include <r_types.h>
#include <r_lib.h>
#include <r_anal.h>

static void mc6809_op_size (const ut8 *data, int *size, int *size_prefix) {
	switch (data[0]) {
		
	}
}

static int mc6809_anal_op (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int ilen;

	memset (op, 0, sizeof(RAnalOp));

	mc6809_op_size (data, &len, &op->nopcode);


}

static int mc6809_anal_archinfo (RAnal *anal, int query) {
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		/* plenty of single byte opcodes */
		return 1;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		/* according to the MC6809 datasheet, 
		   longest opcode is extended indexed addressing
		   e.g. CMPY $7FFF,X */
		return 5;
	default:
		return -1;
	}
}

RAnalPlugin r_anal_plugin_mc6809 = {
	.name = "mc6809",
	.arch = "mc6809",
	.license = "GPL",
	.arch = "mc6809",
	.bits = 8,
	.desc = "MC6809 CPU code analysis plugin",
	.op = mc6809_anal_op,
	.archinfo = mc6809_anal_archinfo,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mc6809,
	.version = R2_VERSION,
};
#endif
