/* radare2 - GPL - Copyright 2016 - gde */

#ifndef MC6809_H
#define MC6809_H

#include <r_asm.h>

/* Minimum and maximum opcode sizes */
/* there are plenty of single byte opcodes */
#define MC6809_MIN_OP_SIZE 1
/* according to the MC6809 datasheet, 
   longest opcode is extended indexed addressing
   e.g. CMPY $7FFF,X */
#define MC6809_MAX_OP_SIZE 5

enum instruction_mode {
	NOMODE = -1,
	INHERENT = 0,
	IMMEDIATE,
	IMMEDIATELONG,
	EXTENDED,
	DIRECT,
	RELATIVE,
	RELATIVELONG,
	TFREXG,
	INDEXED,
	PUSHPULLSYSTEM,
	PUSHPULLUSER,
	PAGE2,
	PAGE3,
};

enum opcode_type {
	MC6809_OP_TYPE_UNK = -1,
	MC6809_OP_TYPE_NOP = 0,

};

typedef struct mc6809_opcodes_t {
	char *name;
	enum instruction_mode mode;
	enum opcode_type type;
} mc6809_opcodes_t;

extern const mc6809_opcodes_t mc6809_opcodes[256];
extern const mc6809_opcodes_t mc6809_page2_opcodes[256];
extern const mc6809_opcodes_t mc6809_page3_opcodes[256];
extern const char *mc6809_register_field[16];
extern const char mc6809_index_registers[];

int mc6809_disassemble(ut64 addr, char *buf_asm, int *op_type, const ut8 *buf, int len);

#endif
