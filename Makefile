GO ?= go
BIN := bin/gotun
BIN_DNS := bin/gotun-dns
BIN_CLIENT := bin/gotun-client
CLIENT_ARM64 := bin/gotun-client-linux-arm64
GOTUN_ARM64 := bin/gotun-linux-arm64
DNS_ARM64 := bin/gotun-dns-linux-arm64
MMDB := data/geo/GeoIP2-City.mmdb

FUZZTIME ?= 30s

.PHONY: all build build-arm64 build-client-arm64 test vet fuzz test-integration test-nft-real test-large-set docker-build docker-build-openwrt test-deploy verify-router check-router fetch-prefixes clean

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
# topology labs. Covers both fixtures: the fast one with netifd and fw3 out of
# the way, and the realistic one with both running.
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
# while the gateway is aarch64, so what is actually likely to take the household
# offline is the binary being for the wrong architecture or the live config
# having drifted, and neither is something a container can tell you about.
#
# Every read is tolerant of its object being absent, and the target always
# completes. That is deliberate: this is a report, and the first version of it
# aborted on `ip -6 route show table 100` -- which exits non-zero on a box with
# no IPv6 routes in that table, i.e. the normal case -- and so stopped before
# printing the nft table and the service states, which are the useful half.
# The gate is `gotun check` on its own; this prints its verdict and carries on.
#
# ROUTER overrides the host: make verify-router ROUTER=root@192.168.8.1
ROUTER ?= root@flint2
SSH ?= ssh -o BatchMode=yes -o ConnectTimeout=10

define rsay
	@echo; echo "== $(1) =="
endef

# check-router stages the aarch64 binary in /tmp and runs `gotun check` with it
# against the live config, then removes it. Nothing is installed and nothing on
# the router changes.
#
# This is the pre-deploy gate, and it closes the one gap the container lab
# cannot: everything there runs amd64 while the gateway is aarch64, so "it
# compiles" was all that had ever been established about the binary that
# actually ships. This runs it on the real CPU against the real file.
check-router: build-arm64
	@echo "== staging $(GOTUN_ARM64) on $(ROUTER), nothing installed =="
	@scp -O -q $(GOTUN_ARM64) $(ROUTER):/tmp/gotun-precheck
	@$(SSH) $(ROUTER) 'chmod +x /tmp/gotun-precheck && /tmp/gotun-precheck check -config /etc/gotun/gotun.conf'; \
		rc=$$?; $(SSH) $(ROUTER) 'rm -f /tmp/gotun-precheck'; \
		if [ $$rc -eq 0 ]; then echo; echo "  -> this binary runs on the router and accepts its live config"; \
		else echo; echo "  -> REFUSED (exit $$rc). Do not deploy until this passes."; fi; \
		exit $$rc

verify-router:
	$(call rsay,architecture and release)
	@$(SSH) $(ROUTER) 'uname -m; sed -n "s/^DISTRIB_DESCRIPTION=//p" /etc/openwrt_release' || true
	$(call rsay,gotun check against the live config)
	@$(SSH) $(ROUTER) 'gotun check -config /etc/gotun/gotun.conf' \
		&& echo "  -> the live config is usable by this binary" \
		|| echo "  -> CHECK FAILED, or this gotun predates the check subcommand; see above"
	$(call rsay,ip rule)
	@$(SSH) $(ROUTER) 'ip rule show; ip -6 rule show' || true
	$(call rsay,table 100)
	@$(SSH) $(ROUTER) 'ip route show table 100 || true; ip -6 route show table 100 || true' || true
	$(call rsay,nft table inet gotun)
	@$(SSH) $(ROUTER) 'nft list table inet gotun 2>&1 | head -30' || true
	@$(SSH) $(ROUTER) 'nft -t list set inet gotun ru_nets 2>/dev/null | grep -c . >/dev/null \
		&& echo "  ru_nets elements: $$(nft list set inet gotun ru_nets 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+" | wc -l)"' || true
	# Supervised services only. gotun-ipsec and fw3 are one-shot -- they do
	# their work and exit -- so asking procd whether they are "running" reads
	# as a fault when it is the normal state. Their effect is reported below
	# instead, which is the thing that actually matters.
	$(call rsay,supervised services)
	@$(SSH) $(ROUTER) 'for s in gotun gotun-dns singbox network; do \
		printf "  %-12s " $$s; \
		if [ -x /etc/init.d/$$s ]; then \
			/etc/init.d/$$s enabled >/dev/null 2>&1 && printf "enabled  " || printf "disabled "; \
			ubus -S call service list "{\"name\":\"$$s\"}" 2>/dev/null | grep -q "\"running\":true" \
				&& echo running || echo "NOT RUNNING"; \
		else echo "not installed"; fi; done' || true
	$(call rsay,one-shot services, by their effect)
	@$(SSH) $(ROUTER) 'printf "  %-20s " "gotun-ipsec"; \
		/etc/init.d/gotun-ipsec enabled >/dev/null 2>&1 && printf "enabled  " || printf "disabled "; \
		ip -br link show 2>/dev/null | grep -qE "^ipsec[0-9]" \
			&& echo "device present" || echo "NO DEVICE"; \
		printf "  %-20s " "firewall"; \
		/etc/init.d/firewall enabled >/dev/null 2>&1 && printf "enabled  " || printf "disabled "; \
		n=$$(iptables -S 2>/dev/null | grep -c zone_); \
		[ "$$n" -gt 0 ] && echo "$$n zone rules" || echo "NO RULES"' || true
	$(call rsay,interfaces)
	@$(SSH) $(ROUTER) 'ip -br link show | grep -E "xray|ipsec|wg|br-lan" || echo "  none"' || true
	$(call rsay,hotplug hooks installed)
	@$(SSH) $(ROUTER) 'ls -l /etc/hotplug.d/iface/*gotun* /etc/hotplug.d/net/*gotun* 2>&1 | sed "s/^/  /"' || true
	$(call rsay,firewall backend)
	@$(SSH) $(ROUTER) 'command -v fw4 >/dev/null && echo "  fw4 (nftables)" || { command -v fw3 >/dev/null && echo "  fw3 (iptables)" || echo "  neither"; }' || true
	@echo

fetch-prefixes: build
	@if [ -f "$(MMDB)" ]; then \
		$(BIN) fetch -mmdb "$(MMDB)" -out prefixes.txt; \
	else \
		echo "No local MMDB at $(MMDB); using MaxMind CSV download (MAXMIND_LICENSE_KEY required)"; \
		$(BIN) fetch -out prefixes.txt; \
	fi

clean:
	rm -rf bin/
