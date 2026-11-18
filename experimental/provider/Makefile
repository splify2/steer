# Isolated Linux lab; deliberately excluded from production source lists.
CC ?= cc
PYTHON ?= python3
BUILD ?= build
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror -pedantic
SDK ?= ../../../plugin-sdk
PROTOCOLS ?= ../../../steer-protocols
CPPFLAGS += -I$(SDK)/include -I../../src/daemon -I$(PROTOCOLS)/src -I$(PROTOCOLS)/src/socks5 -I$(PROTOCOLS)/src/vless
CPPFLAGS += -I../../src/lib -I../../src/third_party/libyaml -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L
STREAM_SRC = stream.c buffers.c operations.c ../../src/daemon/loop.c
ROUTE_STREAM_SRC = $(STREAM_SRC) stream_backend.c binding_lease.c flow_metadata.c route_stream.c
CONFIG_SRC = prototype_config.c ../spec/spec.c ../../src/lib/ynode.c ../../src/lib/err.c ../../src/lib/jsonw.c \
    ../../src/third_party/libyaml/api.c ../../src/third_party/libyaml/reader.c \
    ../../src/third_party/libyaml/scanner.c ../../src/third_party/libyaml/parser.c
HOST_SRC = $(ROUTE_STREAM_SRC) native_stream_backend.c $(CONFIG_SRC) loopback_host.c prototype_prepare.c prototype_store.c route_dial.c resolver.c policy.c policy_route.c $(PROTOCOLS)/src/socks5/codec.c $(PROTOCOLS)/src/vless/inbound.c
LDLIBS += -pthread
UNIT_NAMES = buffers operations admission host lifecycle stream stream-backend stream-backend-fairness policy route-dial prototype-config resolver route-domain prototype-store inbound-tls
UNIT_NAMES += route-stream route-stream-release datagram-routes datagram-registry datagram flow-metadata binding-lease vless-stream vless-stream-deadline
UNIT_NAMES += route-stream-drain host-worker host-worker-namespace host-worker-registration
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
$(BUILD)/inbound-tls-test: inbound_tls.c inbound_tls_test.c inbound_tls.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG inbound_tls.c inbound_tls_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/lifecycle-test: buffers.c operations.c admission.c lifecycle_fixture.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG buffers.c operations.c admission.c lifecycle_fixture.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/stream-test: $(STREAM_SRC) stream_test.c stream.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(STREAM_SRC) stream_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/stream-backend-test: $(STREAM_SRC) stream_backend.c stream_backend_test.c stream_backend.h $(SDK)/include/steer/draft/stream_backend_v1.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(STREAM_SRC) stream_backend.c stream_backend_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/stream-backend-fairness-test: $(STREAM_SRC) stream_backend.c stream_backend_fairness_test.c stream_backend.h $(SDK)/include/steer/draft/stream_backend_v1.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(STREAM_SRC) stream_backend.c stream_backend_fairness_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/route-stream-test: $(ROUTE_STREAM_SRC) native_stream_backend.c route_dial.c resolver.c route_stream_test.c route_stream.h native_stream_backend.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(ROUTE_STREAM_SRC) native_stream_backend.c route_dial.c resolver.c route_stream_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/route-stream-drain-test: route_stream_drain_test.c route_stream.c binding_lease.c flow_metadata.c operations.c ../../src/daemon/loop.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG route_stream_drain_test.c route_stream.c binding_lease.c flow_metadata.c operations.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/route-stream-release-test: $(ROUTE_STREAM_SRC) route_stream_release_test.c route_stream.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(ROUTE_STREAM_SRC) route_stream_release_test.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/datagram-routes-test: datagram_routes_test.c datagram_routes.c datagram.c flow_metadata.c binding_lease.c buffers.c operations.c resolver.c ../../src/daemon/loop.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG datagram_routes_test.c datagram_routes.c datagram.c flow_metadata.c binding_lease.c buffers.c operations.c resolver.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/datagram-registry-test: datagram_registry_test.c datagram_routes.c datagram.c flow_metadata.c binding_lease.c buffers.c operations.c resolver.c ../../src/daemon/loop.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG -DSTEER_DRAFT_DATAGRAM_TEST_HOOKS datagram_registry_test.c datagram_routes.c datagram.c flow_metadata.c binding_lease.c buffers.c operations.c resolver.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/datagram-test: datagram_test.c datagram.c flow_metadata.c buffers.c operations.c resolver.c ../../src/daemon/loop.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG datagram_test.c datagram.c flow_metadata.c buffers.c operations.c resolver.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/flow-metadata-test: flow_metadata_test.c flow_metadata.c flow_metadata.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG flow_metadata_test.c flow_metadata.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/binding-lease-test: binding_lease_test.c binding_lease.c ../../src/daemon/loop.c binding_lease.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG -DSTEER_DRAFT_BINDING_TEST_HOOKS binding_lease_test.c binding_lease.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/vless-stream-test: $(ROUTE_STREAM_SRC) native_stream_backend.c route_dial.c resolver.c vless_stream_backend.c vless_stream_backend_test.c $(PROTOCOLS)/src/vless/outbound.c $(PROTOCOLS)/src/vless/inbound.c $(wildcard *.h) $(PROTOCOLS)/src/vless/outbound.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG $(ROUTE_STREAM_SRC) native_stream_backend.c route_dial.c resolver.c vless_stream_backend.c vless_stream_backend_test.c $(PROTOCOLS)/src/vless/outbound.c $(PROTOCOLS)/src/vless/inbound.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/vless-stream-deadline-test: vless_stream_deadline_test.c vless_stream_backend.c binding_lease.c flow_metadata.c buffers.c operations.c ../../src/daemon/loop.c $(PROTOCOLS)/src/vless/outbound.c $(wildcard *.h) $(PROTOCOLS)/src/vless/outbound.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -UNDEBUG vless_stream_deadline_test.c vless_stream_backend.c binding_lease.c flow_metadata.c buffers.c operations.c ../../src/daemon/loop.c $(PROTOCOLS)/src/vless/outbound.c -Wl,--wrap=loop_timer_set $(LDFLAGS) $(LDLIBS) -o $@
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
$(BUILD)/steer-prototype-startup-signal: $(HOST_SRC) prototype_main.c prototype_startup_signal_wrap.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_SRC) prototype_main.c prototype_startup_signal_wrap.c -Wl,--wrap=loop_run $(LDFLAGS) $(LDLIBS) -o $@

# Header changes must invalidate every lab binary, including sibling SDK changes.
$(UNITS) $(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype: $(wildcard *.h $(SDK)/include/steer/draft/*.h)
$(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype: $(PROTOCOLS)/src/socks5/codec.h $(PROTOCOLS)/src/vless/inbound.h ../../src/daemon/loop.h
$(BUILD)/prototype-config-test $(BUILD)/prototype-store-test $(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype $(BUILD)/steer-prototype-startup-signal: ../spec/spec.h
$(BUILD)/stream-test: ../../src/daemon/loop.h

unit-test: $(UNITS)
	@set -e; for test in $(UNITS); do "$$test"; done
	@set -e; for mode in deadline cancel release resolver; do "$(BUILD)/datagram-routes-test" "$$mode"; done
integration-test: $(BUILD)/socks-loopback $(BUILD)/vless-loopback $(BUILD)/steer-prototype $(BUILD)/steer-prototype-startup-signal
	$(PYTHON) socks_loopback_test.py $(BUILD)/socks-loopback
	$(PYTHON) vless_loopback_test.py $(BUILD)/vless-loopback
	$(PYTHON) prototype_test.py $(BUILD)/steer-prototype
	$(PYTHON) prototype_persistence_test.py $(BUILD)/steer-prototype
	$(PYTHON) prototype_startup_signal_test.py $(BUILD)/steer-prototype-startup-signal
test: unit-test integration-test

# Explicit Linux server profile. Verified dependencies are supplied by caller;
# default/client builds retain their existing dependency and feature surface.
NGTCP2_LIB ?=
WOLFSSL_SERVER_LIB ?=
HY2_SRC = hy2_inbound.c hy2_datagram.c datagram.c datagram_routes.c ../../src/proto/hysteria2/hy2wire.c inbound_tls.c $(PROTOCOLS)/src/hysteria2/server.c \
    $(PROTOCOLS)/src/hysteria2/auth.c $(PROTOCOLS)/src/hysteria2/inbound.c \
    ../../src/proto/quic/quic.c ../../src/proto/quic/qcssl.c
HY2_INC = $(shell find ../../src -type d -printf '-I%p ')
$(BUILD)/steer-prototype-hy2-fault: HY2_TEST_EXTRA = -DSTEER_PREPARE_WRAP_READ prepare_read_fault.c -Wl,--wrap=read -Wl,--wrap=__read_chk
$(BUILD)/steer-prototype-hy2-fault: prepare_read_fault.c
$(BUILD)/steer-prototype-hy2 $(BUILD)/steer-prototype-hy2-fault: $(HOST_SRC) $(HY2_SRC) prototype_main.c $(wildcard *.h) | $(BUILD)
	@test -r "$(NGTCP2_LIB).cflags" -a -r "$(WOLFSSL_SERVER_LIB).cflags"
	@grep -q -- '-DSTEER_WOLFSSL_SERVER' "$(WOLFSSL_SERVER_LIB).cflags"
	@grep -q -- '-DWOLFSSL_VALIDATE_ECC_IMPORT' "$(WOLFSSL_SERVER_LIB).cflags"
	@grep -Eq -- '(^|[[:space:]])-DSTEER_WOLFSSL_POSIX_TIME_SAFE=1([[:space:]]|$$)' "$(WOLFSSL_SERVER_LIB).cflags" || { echo 'rebuild wolfSSL archive with current POSIX time-safe profile' >&2; exit 2; }
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HY2_INC) -DSTEER_PROTOTYPE_HY2 -DQC_WITH_ENDPOINT \
	    $$(cat "$(NGTCP2_LIB).cflags" "$(WOLFSSL_SERVER_LIB).cflags") \
	    $(HOST_SRC) $(HY2_SRC) prototype_main.c "$(NGTCP2_LIB)" "$(WOLFSSL_SERVER_LIB)" \
	    $(HY2_TEST_EXTRA) $(LDFLAGS) $(LDLIBS) -lm -o $@
$(BUILD)/steer-prototype-hy2 $(BUILD)/steer-prototype-hy2-fault: $(wildcard $(PROTOCOLS)/src/hysteria2/*.h $(PROTOCOLS)/src/hysteria2/*.inc) \
    ../../src/proto/quic/quic.h ../../src/proto/quic/qcssl.h ../spec/spec.h \
    $(wildcard $(SDK)/include/steer/draft/*.h) ../../src/daemon/loop.h \
    $(PROTOCOLS)/src/socks5/codec.h $(PROTOCOLS)/src/vless/inbound.h \
    $(if $(NGTCP2_LIB),$(NGTCP2_LIB) $(NGTCP2_LIB).cflags) $(if $(WOLFSSL_SERVER_LIB),$(WOLFSSL_SERVER_LIB) $(WOLFSSL_SERVER_LIB).cflags)
$(BUILD)/prototype-prepare-test: prototype_prepare_test.c prototype_prepare.c inbound_tls.c $(CONFIG_SRC) policy.c \
    ../../src/daemon/loop.c ../../src/proto/quic/quic.c ../../src/proto/quic/qcssl.c $(wildcard *.h) | $(BUILD)
	@test -r "$(NGTCP2_LIB).cflags" -a -r "$(WOLFSSL_SERVER_LIB).cflags"
	@grep -Eq -- '(^|[[:space:]])-DSTEER_WOLFSSL_POSIX_TIME_SAFE=1([[:space:]]|$$)' "$(WOLFSSL_SERVER_LIB).cflags" || { echo 'rebuild wolfSSL archive with current POSIX time-safe profile' >&2; exit 2; }
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HY2_INC) -DQC_WITH_ENDPOINT -DSTEER_PROTOTYPE_HY2 -UNDEBUG \
	    $$(cat "$(NGTCP2_LIB).cflags" "$(WOLFSSL_SERVER_LIB).cflags") \
	    prototype_prepare_test.c prototype_prepare.c inbound_tls.c $(CONFIG_SRC) policy.c \
	    ../../src/daemon/loop.c ../../src/proto/quic/quic.c ../../src/proto/quic/qcssl.c \
	    "$(NGTCP2_LIB)" "$(WOLFSSL_SERVER_LIB)" $(LDFLAGS) $(LDLIBS) -lm -o $@

$(BUILD)/store-fault.so: store_fault.c | $(BUILD)
	$(CC) -O1 -std=c11 -Wall -Wextra -Werror -pedantic -shared -fPIC $< -o $@
store-fault-test: $(BUILD)/steer-prototype $(BUILD)/store-fault.so
	$(PYTHON) prototype_store_fault_test.py $(BUILD)/steer-prototype $(BUILD)/store-fault.so
.PHONY: store-fault-test

$(BUILD)/host-worker-test: host_worker.c host_worker_test.c host_worker.h cancel.h ../../src/daemon/loop.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) host_worker.c host_worker_test.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD)/host-worker-namespace-test: host_worker.c host_worker_namespace_test.c host_worker.h cancel.h ../../src/daemon/loop.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) host_worker.c host_worker_namespace_test.c ../../src/daemon/loop.c $(LDFLAGS) -Wl,--wrap=setns $(LDLIBS) -o $@

$(BUILD)/host-worker-registration-test: host_worker.c host_worker_registration_test.c host_worker.h cancel.h ../../src/daemon/loop.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) host_worker.c host_worker_registration_test.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/host-worker-namespace-actual-test: host_worker.c host_worker_namespace_actual_test.c host_worker.h cancel.h ../../src/daemon/loop.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) host_worker.c host_worker_namespace_actual_test.c ../../src/daemon/loop.c $(LDFLAGS) $(LDLIBS) -o $@
