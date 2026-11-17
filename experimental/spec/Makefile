CC ?= cc
BUILD ?= build
CFLAGS ?= -O2 -g -std=c11 -pedantic -Wall -Wextra -Werror
CPPFLAGS += -I../../src/lib -I../../src/third_party/libyaml -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L
PARSER_SRC = ../../src/lib/ynode.c ../../src/lib/err.c ../../src/lib/jsonw.c \
    ../../src/third_party/libyaml/api.c ../../src/third_party/libyaml/reader.c \
    ../../src/third_party/libyaml/scanner.c ../../src/third_party/libyaml/parser.c
SOURCES = spec.c $(PARSER_SRC)
all: $(BUILD)/steer-spec-compile
$(BUILD):
	mkdir -p $@
$(BUILD)/steer-spec-compile: main.c $(SOURCES) spec.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@
.PHONY: all
