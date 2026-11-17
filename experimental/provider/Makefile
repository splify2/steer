# Isolated Linux lab; deliberately excluded from production source lists.
CC ?= cc
PYTHON ?= python3
BUILD ?= build
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror -pedantic
SDK ?= ../../../plugin-sdk
PROTOCOLS ?= ../../../steer-protocols
CPPFLAGS += -I$(SDK)/include -I../../src/daemon -I$(PROTOCOLS)/src/socks5 -I$(PROTOCOLS)/src/vless
CPPFLAGS += -I../../src/lib -I../../src/third_party/libyaml -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L
STREAM_SRC = stream.c buffers.c operations.c ../../src/daemon/loop.c
CONFIG_SRC = prototype_config.c ../../src/lib/ynode.c ../../src/lib/err.c ../../src/lib/jsonw.c \
    ../../src/third_party/libyaml/api.c ../../src/third_party/libyaml/reader.c \
    ../../src/third_party/libyaml/scanner.c ../../src/third_party/libyaml/parser.c
HOST_SRC = $(STREAM_SRC) $(CONFIG_SRC) loopback_host.c prototype_store.c route_dial.c resolver.c policy.c policy_route.c $(PROTOCOLS)/src/socks5/codec.c $(PROTOCOLS)/src/vless/inbound.c
LDLIBS += -pthread
UNIT_NAMES = buffers operations admission host lifecycle stream policy route-dial prototype-config resolver route-domain prototype-store
UNITS = $(addprefix $(BUILD)/,$(addsuffix -test,$(UNIT_NAMES)))

.PHONY: all test unit-test integration-test
all: $(UNITS) $(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype

$(BUILD):
	mkdir -p $@

$(BUILD)/buffers-test: buffers.c buffers_test.c buffers.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG buffers.c buffers_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/operations-test: operations.c operations_test.c operations.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG operations.c operations_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/admission-test: admission.c admission_test.c admission.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG admission.c admission_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/host-test: buffers.c host_test.c buffers.h host.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG buffers.c host_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/lifecycle-test: buffers.c operations.c admission.c lifecycle_fixture.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG buffers.c operations.c admission.c lifecycle_fixture.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/stream-test: $(STREAM_SRC) stream_test.c stream.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(STREAM_SRC) stream_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/policy-test: policy.c policy_test.c policy_route.c policy.h policy_route.h route_dial.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG policy.c policy_test.c policy_route.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/route-dial-test: $(STREAM_SRC) route_dial.c resolver.c route_dial_test.c route_dial.h resolver.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(STREAM_SRC) route_dial.c resolver.c route_dial_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/prototype-config-test: $(CONFIG_SRC) policy.c prototype_config_test.c prototype_config.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(CONFIG_SRC) policy.c prototype_config_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/prototype-store-test: $(CONFIG_SRC) policy.c prototype_store_test.c prototype_store.c prototype_store.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(CONFIG_SRC) policy.c prototype_store_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/resolver-test: resolver.c resolver_test.c ../../src/daemon/loop.c resolver.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG resolver.c resolver_test.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/route-domain-test: $(STREAM_SRC) route_dial.c resolver.c route_domain_test.c route_dial.h resolver.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(STREAM_SRC) route_dial.c resolver.c route_domain_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/socks-loopback: $(HOST_SRC) socks_loopback.c stream.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_SRC) socks_loopback.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/vless-loopback: $(HOST_SRC) vless_loopback.c stream.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_SRC) vless_loopback.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/steer-prototype: $(HOST_SRC) prototype_main.c stream.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_SRC) prototype_main.c $(LDFLAGS) $(LDLIBS) -o $@

# Header changes must invalidate every lab binary, including sibling SDK changes.
$(UNITS) $(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype: $(wildcard *.h $(SDK)/include/steer/draft/*.h)
$(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype: $(PROTOCOLS)/src/socks5/codec.h $(PROTOCOLS)/src/vless/inbound.h ../../src/daemon/loop.h
$(BUILD)/stream-test: ../../src/daemon/loop.h

unit-test: $(UNITS)
	@set -e; for test in $(UNITS); do "$$test"; done
integration-test: $(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype
	$(PYTHON) socks_loopback_test.py $(BUILD)/socks-loopback
	$(PYTHON) vless_loopback_test.py $(BUILD)/vless-loopback
	$(PYTHON) prototype_test.py $(BUILD)/steer-prototype
	$(PYTHON) prototype_persistence_test.py $(BUILD)/steer-prototype
test: unit-test integration-test

$(BUILD)/store-fault.so: store_fault.c | $(BUILD)
	$(CC) -O1 -std=c11 -Wall -Wextra -Werror -pedantic -shared -fPIC $< -o $@
store-fault-test: $(BUILD)/steer-prototype $(BUILD)/store-fault.so
	$(PYTHON) prototype_store_fault_test.py $(BUILD)/steer-prototype $(BUILD)/store-fault.so
.PHONY: store-fault-test
