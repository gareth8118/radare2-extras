/* radare2 - GPL - Copyright 2016 - gde */

#ifndef MC6809_H
#define MC6809_H

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

typedef struct mc6809_opcodes_t {
	char *name;
	enum instruction_mode mode;
} mc6809_opcodes_t;

extern const mc6809_opcodes_t mc6809_opcodes[256];
extern const mc6809_opcodes_t mc6809_page2_opcodes[256];
extern const mc6809_opcodes_t mc6809_page3_opcodes[256];
extern const char *mc6809_register_field[16];
extern const char mc6809_index_registers[];

#endif
