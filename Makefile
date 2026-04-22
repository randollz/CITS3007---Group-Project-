CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic

# Flags passed to the linker. You will likely need to define this if you use
# additional libraries.
LDFLAGS =

# Sanitizer flags - uncomment during development and testing.
# Do not leave them enabled in a "release" build as they affect performance.
#
# CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g

LIB     = bun_parse.c
MAIN    = main.c
TEST    = tests/test_bun.c

.PHONY: all test clean

all: bun_parser

bun_parser: $(MAIN) $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

# The test binary links the same source files, but not main.c (which has its
# own main()). libcheck provides the test runner's main() instead.
test: tests/test_runner
	./tests/test_runner

tests/test_runner: $(TEST) $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $$(pkg-config --cflags --libs check)

clean:
	-rm bun_parser tests/test_runner *.o
