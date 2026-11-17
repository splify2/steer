CC ?= cc
BUILD ?= build
CFLAGS ?= -O2 -g -std=c11 -pedantic -Wall -Wextra -Werror
CPPFLAGS += -I../../src/lib -I../../src/third_party/libyaml -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L
CPPFLAGS += -I../../../plugin-sdk/include -I../../src/daemon -I../../src/pluginmgr -I../../src/cli
PARSER_SRC = ../../src/lib/ynode.c ../../src/lib/err.c ../../src/lib/jsonw.c \
    ../../src/third_party/libyaml/api.c ../../src/third_party/libyaml/reader.c \
    ../../src/third_party/libyaml/scanner.c ../../src/third_party/libyaml/parser.c
SOURCES = spec.c $(PARSER_SRC)
EXECUTION_SRC = execution.c ../provider/flow_metadata.c ../provider/binding_lease.c \
    ../provider/route_stream.c ../provider/datagram_routes.c ../provider/buffers.c \
    ../provider/operations.c ../../src/daemon/loop.c
all: $(BUILD)/steer-spec-compile
test: $(BUILD)/spec-test $(BUILD)/execution-prepare-test $(BUILD)/execution-owner-test $(BUILD)/execution-journal-test $(BUILD)/execution-async-test $(BUILD)/execution-reservations-test $(BUILD)/device-authority-test $(BUILD)/device-authority-recovery-test $(BUILD)/execution-static-test
	$(BUILD)/spec-test
	$(BUILD)/execution-prepare-test
	$(BUILD)/execution-owner-test
	$(BUILD)/execution-journal-test
	$(BUILD)/execution-async-test
	$(BUILD)/execution-reservations-test
	$(BUILD)/device-authority-test
	$(BUILD)/device-authority-recovery-test
	$(BUILD)/execution-static-test
test-schema: $(BUILD)/steer-spec-compile
	python3 schema_agreement_test.py $(BUILD)/steer-spec-compile
$(BUILD):
	mkdir -p $@
$(BUILD)/steer-spec-compile: main.c $(SOURCES) spec.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) main.c $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/spec-test: spec_test.c $(SOURCES) spec.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) spec_test.c $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/execution-prepare-test: execution_prepare_test.c $(EXECUTION_SRC) execution.h ../provider/cancel.h $(SOURCES) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) execution_prepare_test.c $(EXECUTION_SRC) $(SOURCES) $(LDFLAGS) $(LDLIBS) -pthread -o $@
.PHONY: all test test-schema

EXECUTION_NATIVE_SRC = execution_native.c ../provider/native_stream_backend.c ../provider/stream_backend.c ../provider/stream.c ../provider/route_dial.c ../provider/resolver.c ../provider/datagram.c
$(BUILD)/execution-owner-test: execution_owner_test.c $(EXECUTION_NATIVE_SRC) $(EXECUTION_SRC) $(SOURCES) execution.h execution_native.h ../provider/cancel.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) execution_owner_test.c $(EXECUTION_NATIVE_SRC) $(EXECUTION_SRC) $(SOURCES) $(LDFLAGS) $(LDLIBS) -pthread -o $@

$(BUILD)/execution-journal-test: execution_journal_test.c execution_journal.c execution_journal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) execution_journal_test.c execution_journal.c $(LDFLAGS) -Wl,--wrap=fsync -Wl,--wrap=syscall $(LDLIBS) -o $@

$(BUILD)/execution-async-test: execution_prepare_async_test.c execution_prepare_async.c execution_prepare_async.h ../provider/host_worker.h ../provider/cancel.h ../provider/host_worker.c $(EXECUTION_SRC) $(SOURCES) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) execution_prepare_async_test.c execution_prepare_async.c ../provider/host_worker.c $(EXECUTION_SRC) $(SOURCES) $(LDFLAGS) $(LDLIBS) -pthread -o $@

$(BUILD)/execution-reservations-test: execution_reservations_test.c execution_reservations.c execution_reservations.h execution_journal.c execution_journal.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) execution_reservations_test.c execution_reservations.c execution_journal.c $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/device-authority-test: device_authority_service.c device_authority_service.h device_authority_service_test.c execution_reservations.c execution_journal.c ../provider/host_worker.c ../provider/device_authority.h ../provider/host_worker.h ../provider/cancel.h ../../src/daemon/loop.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) device_authority_service.c device_authority_service_test.c execution_reservations.c execution_journal.c ../provider/host_worker.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -pthread -o $@

$(BUILD)/device-authority-recovery-test: device_authority_service.c device_authority_service.h device_authority_recovery_test.c execution_reservations.c execution_journal.c ../provider/host_worker.c ../provider/device_authority.h ../provider/host_worker.h ../provider/cancel.h ../../src/daemon/loop.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) device_authority_service.c device_authority_recovery_test.c execution_reservations.c execution_journal.c ../provider/host_worker.c ../../src/daemon/loop.c $(LDFLAGS) -Wl,--wrap=fsync -Wl,--wrap=steer_draft_host_worker_submit $(LDLIBS) -pthread -o $@

$(BUILD)/execution-static-test: execution_static.c execution_static.h execution_static_test.c $(EXECUTION_SRC) $(SOURCES) ../../src/pluginmgr/pmver.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) execution_static.c execution_static_test.c $(EXECUTION_SRC) $(SOURCES) ../../src/pluginmgr/pmver.c $(LDFLAGS) $(LDLIBS) -pthread -o $@
