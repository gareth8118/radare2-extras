/* radare2 - GPL - Copyright 2016 - gde */

#include <stdio.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "mc6809.h"


static int mc6809_append_indexed_args (char *buf_asm, const ut8 *buf)
{
	char postop_buffer[32];
	int postop_bytes = 0;

	char index_register = mc6809_index_registers[(buf[0] >> 5) & 0x03];

	if (!(buf[0] & 0x80)) {
		/* Top bit not set - 5 bit offset  */
		/* sign extend a 5 bit offset to 8 */
		st8 offset = (st8) buf[0] & 0x1f;
		if (offset & 0x10) {
			offset |= 0xF0;
		}
		sprintf (postop_buffer, " %d,%c", offset, index_register);
		postop_bytes = 1;
	} else {
		/* The top bit of the first argument byte is set */
		switch (buf[0] & 0x1f) {
		case 0x04:
			/* no offset from register, direct */
			sprintf (postop_buffer,
				 " ,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x08:
			/* 8 bit offset from register, direct */
			sprintf (postop_buffer,
				 " $%02x,%c", buf[1], index_register);
			postop_bytes = 2;
			break;
		case 0x09:
			/* 16 bit offset from register, direct */
			sprintf (postop_buffer,
				 " $%04x,%c", buf[1] * 256 + buf[2],
				 index_register);
			postop_bytes = 3;
			break;
		case 0x06:
			/* accumulator offset from register A */
			sprintf (postop_buffer,
				 " a,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x05:
			/* accumulator offset from register B */
			sprintf (postop_buffer,
				 " b,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x0b:
			/* accumulator offset from register D */
			sprintf (postop_buffer,
				 " d,%c", index_register);
			postop_bytes = 1;
			break;
		case 0x00:
			/* auto increment by 1 from register */
			sprintf (postop_buffer,
				 " ,%c+", index_register);
			postop_bytes = 1;
			break;
		case 0x01:
			/* auto increment by 2 from register */
			sprintf (postop_buffer,
				 " ,%c++", index_register);
			postop_bytes = 1;
			break;
		case 0x02:
			/* auto decrement by 1 from register */
			sprintf (postop_buffer,
				 " ,-%c", index_register);
			postop_bytes = 1;
			break;
		case 0x03:
			/* auto decrement by 2 from register */
			sprintf (postop_buffer,
				 " ,--%c", index_register);
			postop_bytes = 1;
			break;
		case 0x0c:
			/* 8 bit offset from PC */
			sprintf (postop_buffer,
				 " $%02x,pc", buf[1]);
			postop_bytes = 2;
			break;
		case 0x0d:
			/* 16 bit offset from PC */
			sprintf (postop_buffer,
				 " $%04x,pc", buf[1]*256+buf[2]);
			postop_bytes = 3;
			break;
		case 0x14:
			/* no offset from register, indirect */
			sprintf (postop_buffer,
				 " [,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x18:
			/* 8 bit offset from register, indirect */
			sprintf (postop_buffer,
				 " [$%02x,%c]", buf[1], index_register);
			postop_bytes = 2;
			break;
		case 0x19:
			/* 16 bit offset from register, indirect */
			sprintf (postop_buffer,
				 " [$%04x,%c]", buf[1] * 256 + buf[2],
				 index_register);
			postop_bytes = 3;
			break;
		case 0x16:
			/* accumulator offset from register A indirect*/
			sprintf (postop_buffer,
			         " [a,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x15:
			/* accumulator offset from register B indirect */
			sprintf (postop_buffer,
				 " [b,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x1b:
			/* accumulator offset from register D indirect */
			sprintf (postop_buffer,
				 " [d,%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x11:
			/* auto increment by 2 from register indirect */
			sprintf (postop_buffer,
				 " [,%c++]", index_register);
			postop_bytes = 1;
			break;
		case 0x13:
			/* auto decrement by 2 from register indirect */
			sprintf (postop_buffer,
				" [,--%c]", index_register);
			postop_bytes = 1;
			break;
		case 0x1c:
			/* 8 bit offset from PC indirect  */
			sprintf (postop_buffer,
				 " [$%02x,pc]", buf[1]);
			postop_bytes = 2;
			break;
		case 0x1d:
			/* 16 bit offset from PC indirect */
			sprintf (postop_buffer,
				 " [$%04x,pc]", buf[1] * 256 + buf[2]);
			postop_bytes = 3;
			break;
		default:
			if (buf[0] == 0x9f) {
				sprintf (postop_buffer,
				         " [$%04x]", buf[1] * 256 + buf[2]);
				postop_bytes = 3;
				break;
			} else {
				strcpy (postop_buffer, " ???");
				postop_bytes = 1;
			}
		}
	}
	strcat (buf_asm, postop_buffer);
	return postop_bytes;
}

static int mc6809_append_pushpull_args(enum instruction_mode mode,
				       char *buf_asm,
				       const ut8 *opcode_args)
{
	strcat (buf_asm, " ");

	if (*opcode_args & 0x80) {
		strcat (buf_asm, "pc,");
	}
	if (*opcode_args & 0x40) {
		strcat (buf_asm, (mode == PUSHPULLSYSTEM) ? "u," : "s,");
	}
	if (*opcode_args & 0x20) {
		strcat (buf_asm, "y,");
	}
	if (*opcode_args & 0x10) {
		strcat (buf_asm, "x,");
	}
	if (*opcode_args & 0x08) {
		strcat (buf_asm, "dp,");
	}
	if (*opcode_args & 0x04) {
		strcat (buf_asm, "b,");
	}
	if (*opcode_args & 0x02) {
		strcat (buf_asm, "a,");
	}
	if (*opcode_args & 0x01) {
		strcat (buf_asm, "cc,");
	}
	/* Trim off the final unwanted comma */
	buf_asm[strlen(buf_asm)-1] = '\0';
	return 2;
}

static int mc6809_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut8 tfrexg_regmasked;
	const char *tfrexg_source_reg;
	const char *tfrexg_dest_reg;


	const mc6809_opcodes_t *mc6809_opcode = &mc6809_opcodes[buf[0]];
	/* opcode_args points to the first argument byte of the opcode */
	const ut8 *opcode_args = &buf[1];

	op->size = 0;

	switch (mc6809_opcode->mode) {
	case PAGE2:
		/* step past the page 2 prefix */
		mc6809_opcode = &mc6809_page2_opcodes[buf[1]];
		opcode_args++;
		op->size++;
		break;
	case PAGE3:
		/* step past the page 3 prefix */
		mc6809_opcode = &mc6809_page3_opcodes[buf[1]];
		opcode_args++;
		op->size++;
		break;
	default:
		/* non-paged opcode, fall through to the next switch */
		;
	}

	switch (mc6809_opcode->mode) {
	case NOMODE:
	case PAGE2: /* PAGE2 and PAGE3 shouldn't occur twice in a row */
	case PAGE3:
		op->size++;
		strcpy (op->buf_asm, "INVALID");
		break;
	case INHERENT:
		op->size++;
		strcpy (op->buf_asm, mc6809_opcode->name);
		break;
	case IMMEDIATE:
		op->size += 2;
		sprintf (op->buf_asm,
			 "%s #$%02x", mc6809_opcode->name, *opcode_args);
		break;
	case IMMEDIATELONG:
		op->size += 3;
		sprintf (op->buf_asm,
			"%s #$%04x", mc6809_opcode->name,
			opcode_args[0] * 256 + opcode_args[1]);
		break;
	case DIRECT:
		op->size += 2;
		sprintf (op->buf_asm,
			 "%s <$%02x", mc6809_opcode->name, *opcode_args);
		break;
	case RELATIVE:
		op->size += 2;
		sprintf (op->buf_asm, "%s $%04x",
			mc6809_opcode->name,
			(ut16) (a->pc + (st8) *opcode_args + op->size) & 0xFFFF);
		break;
	case RELATIVELONG:
		op->size += 3;
		sprintf (op->buf_asm, "%s $%04x", mc6809_opcode->name,
			(ut16) (a->pc + (st16)(opcode_args[0]*256+opcode_args[1])+op->size) & 0xFFFF);
		break;
	case TFREXG:
		/* In the transfer/exchange mode, both top bits of the
		   nibbles must be identical in a valid opcode */
		tfrexg_regmasked = *opcode_args & 0x88;
		if (tfrexg_regmasked && tfrexg_regmasked != 0x88) {
			op->size += 1;
			strcpy (op->buf_asm, "INVALID");
		} else {
			tfrexg_source_reg = \
				mc6809_register_field[(*opcode_args >> 4) & 0x0f];
			tfrexg_dest_reg = \
				mc6809_register_field[*opcode_args & 0x0f];
			if (!tfrexg_source_reg || !tfrexg_dest_reg) {
				op->size += 1;
				strcpy (op->buf_asm, "INVALID");
			} else {
				op->size += 2;
				sprintf (op->buf_asm,
					 "%s %s,%s",
					 mc6809_opcode->name,
					 tfrexg_source_reg,
					 tfrexg_dest_reg);
			}

		}
		break;
	case INDEXED:
		/* Load Effective Address opcode - variable length */
		strcpy (op->buf_asm, mc6809_opcode->name);
		op->size += mc6809_append_indexed_args (op->buf_asm,
							opcode_args) + 1;
		break;
	case PUSHPULLSYSTEM:
	case PUSHPULLUSER:
		strcpy (op->buf_asm, mc6809_opcode->name);
		op->size += mc6809_append_pushpull_args(mc6809_opcode->mode,
							op->buf_asm,
							opcode_args);
		break;
	case EXTENDED:
		sprintf (op->buf_asm,
			 "%s $%04x",
			 mc6809_opcode->name,
			 opcode_args[0] * 256 + opcode_args[1]);
		op->size += 3;
		break;
	}

	return op->size;
}

RAsmPlugin r_asm_plugin_mc6809 = {
	.name = "mc6809",
	.arch = "mc6809",
	.bits = 8,
	.desc = "Motorola MC6809 disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.license = "GPL",
	.disassemble = &mc6809_disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mc6809,
	.version = R2_VERSION
};
#endif