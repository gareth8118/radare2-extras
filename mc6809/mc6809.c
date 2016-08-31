/* radare2 - GPL - Copyright 2016 - gde */

#include "mc6809.h"
#include <stdio.h>
#include <r_endian.h>

const mc6809_opcodes_t mc6809_opcodes[256] = {
	/* 0x00 */ {"neg",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x01 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x02 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x03 */ {"com",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x04 */ {"lsr",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x05 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x06 */ {"ror",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x07 */ {"asr",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x08 */ {"asl",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x09 */ {"rol",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x0a */ {"dec",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x0b */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x0c */ {"inc",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x0d */ {"tst",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x0e */ {"jmp",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x0f */ {"clr",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x10 */ {"page 2",  PAGE2,          MC6809_OP_TYPE_UNK},
	/* 0x11 */ {"page 3",  PAGE3,          MC6809_OP_TYPE_UNK},
	/* 0x12 */ {"nop",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x13 */ {"sync",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x14 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x15 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x16 */ {"lbra",    RELATIVELONG,   MC6809_OP_TYPE_UNK},
	/* 0x17 */ {"lbsr",    RELATIVELONG,   MC6809_OP_TYPE_UNK},
	/* 0x18 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x19 */ {"daa",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x1a */ {"orcc",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x1b */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x1c */ {"andcc",   IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x1d */ {"sex",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x1e */ {"exg",     TFREXG,         MC6809_OP_TYPE_UNK},
	/* 0x1f */ {"tfr",     TFREXG,         MC6809_OP_TYPE_UNK},
	/* 0x20 */ {"bra",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x21 */ {"brn",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x22 */ {"bhi",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x23 */ {"bls",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x24 */ {"bcc",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x25 */ {"bcs",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x26 */ {"bne",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x27 */ {"beq",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x28 */ {"bvc",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x29 */ {"bvs",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x2a */ {"bpl",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x2b */ {"bmi",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x2c */ {"bge",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x2d */ {"blt",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x2e */ {"bgt",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x2f */ {"ble",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x30 */ {"leax",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x31 */ {"leay",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x32 */ {"leas",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x33 */ {"leau",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x34 */ {"pshs",    PUSHPULLSYSTEM, MC6809_OP_TYPE_UNK},
	/* 0x35 */ {"puls",    PUSHPULLSYSTEM, MC6809_OP_TYPE_UNK},
	/* 0x36 */ {"pshu",    PUSHPULLUSER,   MC6809_OP_TYPE_UNK},
	/* 0x37 */ {"pulu",    PUSHPULLUSER,   MC6809_OP_TYPE_UNK},
	/* 0x38 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x39 */ {"rts",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x3a */ {"abx",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x3b */ {"rti",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x3c */ {"cwai",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x3d */ {"mul",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x3e */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x3f */ {"swi",     INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x40 */ {"nega",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x41 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x42 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x43 */ {"coma",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x44 */ {"lsra",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x45 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x46 */ {"rora",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x47 */ {"asra",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x48 */ {"asla",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x49 */ {"rola",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x4a */ {"deca",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x4b */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x4c */ {"inca",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x4d */ {"tsta",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x4e */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x4f */ {"clra",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x50 */ {"negb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x51 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x52 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x53 */ {"comb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x54 */ {"lsrb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x55 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x56 */ {"rorb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x57 */ {"asrb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x58 */ {"aslb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x59 */ {"rolb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x5a */ {"decb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x5b */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x5c */ {"incb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x5d */ {"tstb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x5e */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x5f */ {"clrb",    INHERENT,       MC6809_OP_TYPE_UNK},
	/* 0x60 */ {"neg",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x61 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x62 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x63 */ {"com",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x64 */ {"lsr",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x65 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x66 */ {"ror",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x67 */ {"asr",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x68 */ {"asl",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x69 */ {"rol",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x6a */ {"dec",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x6b */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x6c */ {"inc",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x6d */ {"tst",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x6e */ {"jmp",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x6f */ {"clr",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0x70 */ {"neg",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x71 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x72 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x73 */ {"com",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x74 */ {"lsr",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x75 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x76 */ {"ror",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x77 */ {"asr",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x78 */ {"asl",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x79 */ {"rol",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x7a */ {"dec",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x7b */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x7c */ {"inc",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x7d */ {"tst",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x7e */ {"jmp",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x7f */ {"clr",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0x80 */ {"suba",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x81 */ {"cmpa",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x82 */ {"sbca",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x83 */ {"subd",    IMMEDIATELONG,  MC6809_OP_TYPE_UNK},
	/* 0x84 */ {"anda",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x85 */ {"bita",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x86 */ {"lda",     IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x87 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x88 */ {"eora",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x89 */ {"adca",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x8a */ {"ora",     IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x8b */ {"adda",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0x8c */ {"cmpx",    IMMEDIATELONG,  MC6809_OP_TYPE_UNK},
	/* 0x8d */ {"bsr",     RELATIVE,       MC6809_OP_TYPE_UNK},
	/* 0x8e */ {"ldx",     IMMEDIATELONG,  MC6809_OP_TYPE_UNK},
	/* 0x8f */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0x90 */ {"suba",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x91 */ {"cmpa",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x92 */ {"sbca",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x93 */ {"subd",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x94 */ {"anda",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x95 */ {"bita",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x96 */ {"lda",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x97 */ {"sta",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x98 */ {"eora",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x99 */ {"adca",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x9a */ {"ora",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x9b */ {"adda",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x9c */ {"cmpx",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x9d */ {"jsr",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x9e */ {"ldx",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0x9f */ {"stx",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xa0 */ {"suba",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa1 */ {"cmpa",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa2 */ {"sbca",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa3 */ {"subd",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa4 */ {"anda",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa5 */ {"bita",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa6 */ {"lda",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa7 */ {"sta",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa8 */ {"eora",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xa9 */ {"adca",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xaa */ {"ora",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xab */ {"adda",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xac */ {"cmpx",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xad */ {"jsr",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xae */ {"ldx",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xaf */ {"stx",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xb0 */ {"suba",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb1 */ {"cmpa",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb2 */ {"sbca",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb3 */ {"subd",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb4 */ {"anda",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb5 */ {"bita",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb6 */ {"lda",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb7 */ {"sta",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb8 */ {"eora",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xb9 */ {"adca",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xba */ {"ora",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xbb */ {"adda",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xbc */ {"cmpx",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xbd */ {"jsr",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xbe */ {"ldx",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xbf */ {"stx",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xc0 */ {"subb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc1 */ {"cmpb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc2 */ {"sbcb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc3 */ {"addd",    IMMEDIATELONG,  MC6809_OP_TYPE_UNK},
	/* 0xc4 */ {"andb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc5 */ {"bitb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc6 */ {"ldb",     IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc7 */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0xc8 */ {"eorb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xc9 */ {"adcb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xca */ {"orb",     IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xcb */ {"addb",    IMMEDIATE,      MC6809_OP_TYPE_UNK},
	/* 0xcc */ {"ldd",     IMMEDIATELONG,  MC6809_OP_TYPE_UNK},
	/* 0xcd */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0xce */ {"ldu",     IMMEDIATELONG,  MC6809_OP_TYPE_UNK},
	/* 0xcf */ {"invalid", NOMODE,         MC6809_OP_TYPE_UNK},
	/* 0xd0 */ {"subb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd1 */ {"cmpb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd2 */ {"sbcb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd3 */ {"addd",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd4 */ {"andb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd5 */ {"bitb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd6 */ {"ldb",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd7 */ {"stb",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd8 */ {"eorb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xd9 */ {"adcb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xda */ {"orb",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xdb */ {"addb",    DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xdc */ {"ldd",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xdd */ {"std",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xde */ {"ldu",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xdf */ {"stu",     DIRECT,         MC6809_OP_TYPE_UNK},
	/* 0xe0 */ {"subb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe1 */ {"cmpb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe2 */ {"sbcb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe3 */ {"addd",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe4 */ {"andb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe5 */ {"bitb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe6 */ {"ldb",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe7 */ {"stb",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe8 */ {"eorb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xe9 */ {"adcb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xea */ {"orb",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xeb */ {"addb",    INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xec */ {"ldd",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xed */ {"std",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xee */ {"ldu",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xef */ {"stu",     INDEXED,        MC6809_OP_TYPE_UNK},
	/* 0xf0 */ {"subb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf1 */ {"cmpb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf2 */ {"sbcb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf3 */ {"addd",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf4 */ {"andb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf5 */ {"bitb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf6 */ {"ldb",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf7 */ {"stb",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf8 */ {"eorb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xf9 */ {"adcb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xfa */ {"orb",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xfb */ {"addb",    EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xfc */ {"ldd",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xfd */ {"std",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xfe */ {"ldu",     EXTENDED,       MC6809_OP_TYPE_UNK},
	/* 0xff */ {"stu",     EXTENDED,       MC6809_OP_TYPE_UNK},
};

const mc6809_opcodes_t mc6809_page2_opcodes[256] = {
	/* 0x1000 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1001 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1002 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1003 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1004 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1005 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1006 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1007 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1008 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1009 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x100a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x100b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x100c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x100d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x100e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x100f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1010 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1011 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1012 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1013 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1014 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1015 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1016 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1017 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1018 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1019 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x101a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x101b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x101c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x101d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x101e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x101f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1020 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1021 */ {"lbrn",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1022 */ {"lbhi",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1023 */ {"lbls",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1024 */ {"lbhs",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1025 */ {"lbcs",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1026 */ {"lbne",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1027 */ {"lbeq",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1028 */ {"lbvc",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1029 */ {"lbvs",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x102a */ {"lbpl",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x102b */ {"lbmi",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x102c */ {"lbge",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x102d */ {"lblt",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x102e */ {"lbgt",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x102f */ {"lble",    RELATIVELONG, MC6809_OP_TYPE_UNK},
	/* 0x1030 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1031 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1032 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1033 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1034 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1035 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1036 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1037 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1038 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1039 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x103a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x103b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x103c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x103d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x103e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x103f */ {"swi2",    INHERENT,     MC6809_OP_TYPE_UNK},
	/* 0x1040 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1041 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1042 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1043 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1044 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1045 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1046 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1047 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1048 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1049 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x104a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x104b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x104c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x104d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x104e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x104f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1050 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1051 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1052 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1053 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1054 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1055 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1056 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1057 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1058 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1059 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x105a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x105b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x105c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x105d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x105e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x105f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1060 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1061 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1062 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1063 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1064 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1065 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1066 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1067 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1068 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1069 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x106a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x106b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x106c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x106d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x106e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x106f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1070 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1071 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1072 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1073 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1074 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1075 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1076 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1077 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1078 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1079 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x107a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x107b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x107c */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x107d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x107e */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x107f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1080 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1081 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1082 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1083 */ {"cmpd",    IMMEDIATELONG, MC6809_OP_TYPE_UNK},
	/* 0x1084 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1085 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1086 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1087 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1088 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1089 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x108a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x108b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x108c */ {"cmpy",    IMMEDIATELONG, MC6809_OP_TYPE_UNK},
	/* 0x108d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x108e */ {"ldy",     IMMEDIATELONG, MC6809_OP_TYPE_UNK},
	/* 0x108f */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1090 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1091 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1092 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1093 */ {"cmpd",    DIRECT,       MC6809_OP_TYPE_UNK},
	/* 0x1094 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1095 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1096 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1097 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1098 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x1099 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x109a */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x109b */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x109c */ {"cmpy",    DIRECT,       MC6809_OP_TYPE_UNK},
	/* 0x109d */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x109e */ {"ldy",     DIRECT,       MC6809_OP_TYPE_UNK},
	/* 0x109f */ {"sty",     DIRECT,       MC6809_OP_TYPE_UNK},
	/* 0x10a0 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a1 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a2 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a3 */ {"cmpd",    INDEXED,      MC6809_OP_TYPE_UNK},
	/* 0x10a4 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a5 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a6 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a7 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a8 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10a9 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10aa */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ab */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ac */ {"cmpy",    INDEXED,      MC6809_OP_TYPE_UNK},
	/* 0x10ad */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ae */ {"ldy",     INDEXED,      MC6809_OP_TYPE_UNK},
	/* 0x10af */ {"sty",     INDEXED,      MC6809_OP_TYPE_UNK},
	/* 0x10b0 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b1 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b2 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b3 */ {"cmpd",    EXTENDED,     MC6809_OP_TYPE_UNK},
	/* 0x10b4 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b5 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b6 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b7 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b8 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10b9 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ba */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10bb */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10bc */ {"cmpy",    EXTENDED,     MC6809_OP_TYPE_UNK},
	/* 0x10bd */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10be */ {"ldy",     EXTENDED,     MC6809_OP_TYPE_UNK},
	/* 0x10bf */ {"sty",     EXTENDED,     MC6809_OP_TYPE_UNK},
	/* 0x10c0 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c1 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c2 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c3 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c4 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c5 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c6 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c7 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c8 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10c9 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ca */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10cb */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10cc */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10cd */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ce */ {"lds",     IMMEDIATELONG, MC6809_OP_TYPE_UNK},
	/* 0x10cf */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d0 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d1 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d2 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d3 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d4 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d5 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d6 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d7 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d8 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10d9 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10da */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10db */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10dc */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10dd */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10de */ {"lds",     DIRECT,       MC6809_OP_TYPE_UNK},
	/* 0x10df */ {"sts",     DIRECT,       MC6809_OP_TYPE_UNK},
	/* 0x10e0 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e1 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e2 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e3 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e4 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e5 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e6 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e7 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e8 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10e9 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ea */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10eb */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ec */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ed */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10ee */ {"lds",     INDEXED,      MC6809_OP_TYPE_UNK},
	/* 0x10ef */ {"sts",     INDEXED,      MC6809_OP_TYPE_UNK},
	/* 0x10f0 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f1 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f2 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f3 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f4 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f5 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f6 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f7 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f8 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10f9 */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10fa */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10fb */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10fc */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10fd */ {"invalid", NOMODE,       MC6809_OP_TYPE_UNK},
	/* 0x10fe */ {"lds",     EXTENDED,     MC6809_OP_TYPE_UNK},
	/* 0x10ff */ {"sts",     EXTENDED,     MC6809_OP_TYPE_UNK},
};

const mc6809_opcodes_t mc6809_page3_opcodes[256] = {
	/* 0x1100 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1101 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1102 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1103 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1104 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1105 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1106 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1107 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1108 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1109 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x110a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x110b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x110c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x110d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x110e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x110f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1110 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1111 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1112 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1113 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1114 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1115 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1116 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1117 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1118 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1119 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x111a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x111b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x111c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x111d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x111e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x111f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1120 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1121 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1122 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1123 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1124 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1125 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1126 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1127 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1128 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1129 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x112a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x112b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x112c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x112d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x112e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x112f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1130 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1131 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1132 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1133 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1134 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1135 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1136 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1137 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1138 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1139 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x113a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x113b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x113c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x113d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x113e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x113f */ {"swi3", INHERENT, MC6809_OP_TYPE_UNK},
	/* 0x1140 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1141 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1142 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1143 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1144 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1145 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1146 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1147 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1148 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1149 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x114a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x114b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x114c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x114d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x114e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x114f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1150 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1151 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1152 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1153 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1154 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1155 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1156 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1157 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1158 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1159 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x115a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x115b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x115c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x115d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x115e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x115f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1160 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1161 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1162 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1163 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1164 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1165 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1166 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1167 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1168 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1169 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x116a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x116b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x116c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x116d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x116e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x116f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1170 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1171 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1172 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1173 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1174 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1175 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1176 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1177 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1178 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1179 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x117a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x117b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x117c */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x117d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x117e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x117f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1180 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1181 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1182 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1183 */ {"cmpu", IMMEDIATELONG, MC6809_OP_TYPE_UNK},
	/* 0x1184 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1185 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1186 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1187 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1188 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1189 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x118a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x118b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x118c */ {"cmps", IMMEDIATELONG, MC6809_OP_TYPE_UNK},
	/* 0x118d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x118e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x118f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1190 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1191 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1192 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1193 */ {"cmpu", DIRECT, MC6809_OP_TYPE_UNK},
	/* 0x1194 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1195 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1196 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1197 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1198 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x1199 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x119a */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x119b */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x119c */ {"cmps", DIRECT, MC6809_OP_TYPE_UNK},
	/* 0x119d */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x119e */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x119f */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a0 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a1 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a2 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a3 */ {"cmpu", INDEXED, MC6809_OP_TYPE_UNK},
	/* 0x11a4 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a5 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a6 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a7 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a8 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11a9 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11aa */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ab */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ac */ {"cmps", INDEXED, MC6809_OP_TYPE_UNK},
	/* 0x11ad */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ae */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11af */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b0 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b1 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b2 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b3 */ {"cmpu", EXTENDED, MC6809_OP_TYPE_UNK},
	/* 0x11b4 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b5 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b6 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b7 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b8 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11b9 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ba */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11bb */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11bc */ {"cmps", EXTENDED, MC6809_OP_TYPE_UNK},
	/* 0x11bd */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11be */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11bf */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c0 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c1 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c2 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c3 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c4 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c5 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c6 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c7 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c8 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11c9 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ca */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11cb */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11cc */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11cd */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ce */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11cf */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d0 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d1 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d2 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d3 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d4 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d5 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d6 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d7 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d8 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11d9 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11da */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11db */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11dc */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11dd */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11de */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11df */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e0 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e1 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e2 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e3 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e4 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e5 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e6 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e7 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e8 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11e9 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ea */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11eb */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ec */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ed */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ee */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ef */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f0 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f1 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f2 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f3 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f4 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f5 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f6 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f7 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f8 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11f9 */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11fa */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11fb */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11fc */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11fd */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11fe */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
	/* 0x11ff */ {"invalid", NOMODE, MC6809_OP_TYPE_UNK},
};

const char *mc6809_register_field[16] = {
	/* 0b0000 */ "d",
	/* 0b0001 */ "x",
	/* 0b0010 */ "y",
	/* 0b0011 */ "u",
	/* 0b0100 */ "s",
	/* 0b0101 */ "pc",
	/* 0b0110 */ NULL,
	/* 0b0111 */ NULL,
	/* 0b1000 */ "a",
	/* 0b1001 */ "b",
	/* 0b1010 */ "ccr",
	/* 0b1011 */ "dpr",
};

const char mc6809_index_registers[] = {
	/* 0b00 */ 'x',
	/* 0b01 */ 'y',
	/* 0b10 */ 'u',
	/* 0b11 */ 's',
};

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
				 " $%04x,%c", r_read_be16 (&buf[1]),
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
				 " $%04x,pc", r_read_be16 (&buf[1]));
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
				 " [$%04x,%c]", r_read_be16 (&buf[1]),
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
				 " [$%04x,pc]", r_read_be16 (&buf[1]));
			postop_bytes = 3;
			break;
		default:
			if (buf[0] == 0x9f) {
				sprintf (postop_buffer,
				         " [$%04x]", r_read_be16 (&buf[1]));
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

int mc6809_disassemble(ut64 addr, char *buf_asm, int *op_type, const ut8 *buf, int len) {
	int size;
	ut8 tfrexg_regmasked;
	const char *tfrexg_source_reg;
	const char *tfrexg_dest_reg;


	const mc6809_opcodes_t *mc6809_opcode = &mc6809_opcodes[buf[0]];
	/* opcode_args points to the first argument byte of the opcode */
	const ut8 *opcode_args = &buf[1];

	size = 0;

	switch (mc6809_opcode->mode) {
	case PAGE2:
		/* step past the page 2 prefix */
		mc6809_opcode = &mc6809_page2_opcodes[buf[1]];
		opcode_args++;
		size++;
		break;
	case PAGE3:
		/* step past the page 3 prefix */
		mc6809_opcode = &mc6809_page3_opcodes[buf[1]];
		opcode_args++;
		size++;
		break;
	default:
		/* non-paged opcode, fall through to the next switch */
		;
	}

	switch (mc6809_opcode->mode) {
	case NOMODE:
	case PAGE2: /* PAGE2 and PAGE3 shouldn't occur twice in a row */
	case PAGE3:
		size++;
		strcpy (buf_asm, "INVALID");
		break;
	case INHERENT:
		size++;
		strcpy (buf_asm, mc6809_opcode->name);
		break;
	case IMMEDIATE:
		size += 2;
		sprintf (buf_asm,
			 "%s #$%02x", mc6809_opcode->name, *opcode_args);
		break;
	case IMMEDIATELONG:
		size += 3;
		sprintf (buf_asm,
			"%s #$%04x", mc6809_opcode->name,
			r_read_be16 (opcode_args));
		break;
	case DIRECT:
		size += 2;
		sprintf (buf_asm,
			 "%s <$%02x", mc6809_opcode->name, *opcode_args);
		break;
	case RELATIVE:
		size += 2;
		sprintf (buf_asm, "%s $%04x",
			mc6809_opcode->name,
			(ut16) (addr + (st8) *opcode_args + size) & 0xFFFF);
		break;
	case RELATIVELONG:
		size += 3;
		sprintf (buf_asm, "%s $%04x", mc6809_opcode->name,
			(ut16) (addr + (st16)(r_read_be16 (opcode_args))+size) & 0xFFFF);
		break;
	case TFREXG:
		/* In the transfer/exchange mode, both top bits of the
		   nibbles must be identical in a valid opcode */
		tfrexg_regmasked = *opcode_args & 0x88;
		if (tfrexg_regmasked && tfrexg_regmasked != 0x88) {
			size += 1;
			strcpy (buf_asm, "INVALID");
		} else {
			tfrexg_source_reg = \
				mc6809_register_field[(*opcode_args >> 4) & 0x0f];
			tfrexg_dest_reg = \
				mc6809_register_field[*opcode_args & 0x0f];
			if (!tfrexg_source_reg || !tfrexg_dest_reg) {
				size += 1;
				strcpy (buf_asm, "INVALID");
			} else {
				size += 2;
				sprintf (buf_asm,
					 "%s %s,%s",
					 mc6809_opcode->name,
					 tfrexg_source_reg,
					 tfrexg_dest_reg);
			}

		}
		break;
	case INDEXED:
		/* Load Effective Address opcode - variable length */
		strcpy (buf_asm, mc6809_opcode->name);
		size += mc6809_append_indexed_args (buf_asm,
						    opcode_args) + 1;
		break;
	case PUSHPULLSYSTEM:
	case PUSHPULLUSER:
		strcpy (buf_asm, mc6809_opcode->name);
		size += mc6809_append_pushpull_args(mc6809_opcode->mode,
						    buf_asm,
						    opcode_args);
		break;
	case EXTENDED:
		sprintf (buf_asm,
			 "%s $%04x",
			 mc6809_opcode->name,
			 r_read_be16 (opcode_args));
		size += 3;
		break;
	}

	return size;
}

