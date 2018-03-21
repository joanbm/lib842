CC=gcc
CC_FLAGS=-Wall -fPIC -g -O3


MODULES   := serial serial_optimized
OBJ_DIR := $(addprefix obj/,$(MODULES))
BIN_DIR := $(addprefix bin/,$(MODULES))

SRC_DIR_SERIAL := src/serial
OBJ_DIR_SERIAL := obj/serial

SRC_FILES_SERIAL := $(wildcard $(SRC_DIR_SERIAL)/*.c)
OBJ_FILES_SERIAL := $(patsubst $(SRC_DIR_SERIAL)/%.c,$(OBJ_DIR_SERIAL)/%.o,$(SRC_FILES_SERIAL))

SRC_DIR_SERIAL_OPT := src/serial_optimized
OBJ_DIR_SERIAL_OPT := obj/serial_optimized

SRC_FILES_SERIAL_OPT := $(wildcard $(SRC_DIR_SERIAL_OPT)/*.c)
OBJ_FILES_SERIAL_OPT := $(patsubst $(SRC_DIR_SERIAL_OPT)/%.c,$(OBJ_DIR_SERIAL_OPT)/%.o,$(SRC_FILES_SERIAL_OPT))

.PHONY: all checkdirs clean
#.check-env:

all: checkdirs standalone

$(OBJ_DIR_SERIAL)/%.o: $(SRC_DIR_SERIAL)/%.c
	$(CC) $(CC_FLAGS) -c $< -o $@

$(OBJ_DIR_SERIAL_OPT)/%.o: $(SRC_DIR_SERIAL_OPT)/%.c
	$(CC) $(CC_FLAGS) -c $< -o $@

serial_lib: checkdirs $(OBJ_FILES_SERIAL)
	$(CC) $(CC_FLAGS) -shared -Wl,-soname,lib842.so -Wl,--no-as-needed -o bin/serial/lib842.so $(OBJ_FILES_SERIAL)

clean:
	rm -Rf obj
	rm -Rf bin
	rm -Rf test/simple_test

checkdirs: $(OBJ_DIR) $(BIN_DIR)

test_serial_standalone: checkdirs $(OBJ_FILES_SERIAL)
	$(CC) $(CC_FLAGS) $(OBJ_FILES_SERIAL) test/simple_test.c -o bin/serial/simple_test -I./include 
	bin/serial/simple_test

test_serial_lib: serial_lib
	$(CC) $(CC_FLAGS) test/simple_test.c -o test/simple_test -I./include -L./bin/serial/ -l842
	LD_LIBRARY_PATH=$(shell pwd)/$(BIN_DIR):$(shell echo $$LD_LIBRARY_PATH) test/simple_test

test_serial_optimized_standalone: checkdirs $(OBJ_FILES_SERIAL_OPT)
	$(CC) $(CC_FLAGS) $(OBJ_FILES_SERIAL_OPT) test/simple_test.c -o bin/serial_optimized/simple_test -I./include 
	bin/serial_optimized/simple_test

standalone: test_serial_standalone test_serial_optimized_standalone

libs: serial_lib

test_libs: test_serial_lib

$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@
