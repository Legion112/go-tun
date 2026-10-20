GO ?= go
BIN := bin/gotun
BIN_DNS := bin/gotun-dns
BIN_CLIENT := bin/gotun-client
CLIENT_ARM64 := bin/gotun-client-linux-arm64
GOTUN_ARM64 := bin/gotun-linux-arm64
DNS_ARM64 := bin/gotun-dns-linux-arm64
MMDB := data/geo/GeoIP2-City.mmdb

FUZZTIME ?= 30s

.PHONY: all build build-arm64 build-client-arm64 test vet fuzz test-integration test-nft-real test-large-set docker-build docker-build-openwrt test-deploy verify-router fetch-prefixes clean

all: build test

build:
	mkdir -p bin
	$(GO) build -o $(BIN) ./cmd/gotun
	$(GO) build -o $(BIN_DNS) ./cmd/gotun-dns
	$(GO) build -o $(BIN_CLIENT) ./cmd/gotun-client

# The router is aarch64. Static and trimmed: OpenWrt has no glibc, so a cgo build
# would not run there at all.
build-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o $(GOTUN_ARM64) ./cmd/gotun
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o $(DNS_ARM64) ./cmd/gotun-dns

# Suffixed output so an amd64 binary can never be scp'd to an arm64 client.
build-client-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o $(CLIENT_ARM64) ./cmd/gotun-client

test:
	$(GO) test ./...

# The default invocation does not vet the integration-tagged files, which is
# where a good deal of the lab code lives.
vet:
	$(GO) vet ./...
	$(GO) vet -tags=integration ./test/integration/...

# go test takes one -fuzz target per invocation, so a loop is the only way to
# cover all three.
fuzz:
	@for t in FuzzCollapseIPv4 FuzzCollapseIPv6 FuzzCollapseMixed; do \
		echo "== $$t"; \
		$(GO) test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) ./internal/prefixes/ || exit 1; \
	done

# The real-nft round trips live in internal/linux/nftables, outside the path
# test-integration walks, so until this target existed they were compiled by
# make test and skipped there, and run by nothing at all.
test-nft-real: docker-build
	GOTUN_INTEGRATION=1 $(GO) test -count=1 -timeout 5m ./internal/linux/nftables/ -run 'RealNftRoundTrip'

test-integration: docker-build docker-build-openwrt test-nft-real
	GOTUN_INTEGRATION=1 $(GO) test -tags=integration -count=1 -timeout 15m ./test/integration/...

# Just the deploy lab, for iterating on deploy/openwrt/ without waiting for the
# topology labs.
test-deploy: docker-build-openwrt
	GOTUN_INTEGRATION=1 $(GO) test -tags=integration -count=1 -timeout 15m ./test/integration/ -run OpenWrt

test-large-set: docker-build
	GOTUN_LARGE_SET=1 $(GO) test -count=1 -timeout 20m ./internal/linux/nftables/ -run 'LargeRUSet'

docker-build:
	docker build -t gotun:lab .

# Depends on docker-build: the OpenWrt image copies its binaries out of
# gotun:lab rather than rebuilding them, so both labs run byte-identical
# binaries and this image costs no extra Go compilation.
docker-build-openwrt: docker-build
	docker build -t gotun:openwrt -f test/integration/openwrt/Dockerfile .

# verify-router is read-only: it reads the live gateway and changes nothing.
#
# It is the pre-deploy gate the container tests cannot be. The lab runs amd64
# against a container with no netifd and no fw3; the gateway is aarch64 with
# both. What is actually likely to take the household offline is the binary
# being for the wrong architecture or the live config having drifted, and
# neither is something a container can tell you about.
#
# ROUTER overrides the host: make verify-router ROUTER=root@192.168.8.1
ROUTER ?= root@flint2

verify-router:
	@echo "== gotun check against the live config =="
	@ssh $(ROUTER) 'gotun check -config /etc/gotun/gotun.conf' || true
	@echo
	@echo "== ip rule =="
	@ssh $(ROUTER) 'ip rule show'
	@echo
	@echo "== table 100 =="
	@ssh $(ROUTER) 'ip route show table 100; ip -6 route show table 100'
	@echo
	@echo "== nft table inet gotun =="
	@ssh $(ROUTER) 'nft list table inet gotun | head -40'
	@echo
	@echo "== services =="
	@ssh $(ROUTER) 'for s in gotun gotun-dns gotun-ipsec singbox; do \
		printf "%-12s " $$s; \
		if [ -x /etc/init.d/$$s ]; then \
			/etc/init.d/$$s enabled >/dev/null 2>&1 && printf "enabled " || printf "disabled "; \
			ubus -S call service list "{\"name\":\"$$s\"}" 2>/dev/null | grep -q "\"running\":true" \
				&& echo running || echo "not running"; \
		else echo "not installed"; fi; done'
	@echo
	@echo "== tunnel device =="
	@ssh $(ROUTER) 'ip -br link show | grep -E "xray|ipsec|wg" || echo "none"'

fetch-prefixes: build
	@if [ -f "$(MMDB)" ]; then \
		$(BIN) fetch -mmdb "$(MMDB)" -out prefixes.txt; \
	else \
		echo "No local MMDB at $(MMDB); using MaxMind CSV download (MAXMIND_LICENSE_KEY required)"; \
		$(BIN) fetch -out prefixes.txt; \
	fi

clean:
	rm -rf bin/
