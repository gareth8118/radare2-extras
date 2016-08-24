include ../options.mk

CFLAGS+=$(R2_CFLAGS) -Wall -shared -fPIC -DLIL_ENDIAN=1
LDFLAGS+=$(R2_LDFLAGS) $(LINK) -lr_util

TARGET_ASM=asm_mc6809.$(LIBEXT)
TARGET_ANAL=anal_mc6809.$(LIBEXT)

OBJ_ASM=asm_mc6809.o mc6809.o
OBJ_ANAL=anal_mc6809.o mc6809.o

ALL_TARGETS=$(TARGET_ASM) $(TARGET_ANAL)

all: $(ALL_TARGETS)

$(TARGET_ASM): $(OBJ_ASM)
	$(CC) $(call libname,asm_mc6809) $(LDFLAGS) \
		$(CFLAGS) -o $(TARGET_ASM) $(OBJ_ASM)

$(TARGET_ANAL): $(OBJ_ANAL)
	$(CC) $(call libname,anal_mc6809) $(LDFLAGS) \
		$(CFLAGS) -o $(TARGET_ANAL) $(OBJ_ANAL)

clean:
	rm -f *.$(LIBEXT) *.o