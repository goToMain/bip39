#
#  Copyright (c) 2023 Siddharth Chandrasekaran <sidcha.dev@gmail.com>
#
#  SPDX-License-Identifier: Apache-2.0
#

O        ?= obj
NAME     ?= bip39
SRC      := src/bip39.c src/sha256.c
OBJ      := $(SRC:%.c=$(O)/%.o)
TEST_SRC := test/test.c
TEST_OBJ := $(TEST_SRC:%.c=$(O)/%.o)
CCFLAGS ?= -Wall -O3

ifeq ($(V),)
Q    := @
else
Q    :=
endif

CCFLAGS += -I ../sha/

.PHONY: all
all: $(O)/lib$(NAME).a
	@echo > /dev/null

$(O)/lib$(NAME).a: $(OBJ)
	@echo "  AR $(@F)"
	$(Q)$(AR) -qc $@ $^

$(O)/%.o: %.c
	@echo "  CC $<"
	@mkdir -p $(@D)
	$(Q)$(CC) -c $< $(CCFLAGS) -Iinclude/ -o $@

$(O)/test.bin: $(O)/lib$(NAME).a $(TEST_OBJ)
	$(Q)$(CC) -o $@ -g -L $(O) -l bip39 $^

.PHONY: test
check: $(O)/test.bin
	$(Q)./$(O)/test.bin

.PHONY: clean
clean:
	$(Q)rm -f $(OBJ) $(TEST_OBJ) $(O)/lib$(NAME).a $(O)/test.bin
