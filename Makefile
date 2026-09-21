GO ?= go
BIN := bin/gotun
BIN_DNS := bin/gotun-dns
BIN_CLIENT := bin/gotun-client
CLIENT_ARM64 := bin/gotun-client-linux-arm64
GOTUN_ARM64 := bin/gotun-linux-arm64
MMDB := data/geo/GeoIP2-City.mmdb

FUZZTIME ?= 30s

.PHONY: all build build-arm64 build-client-arm64 test vet fuzz test-integration test-nft-real test-large-set docker-build fetch-prefixes clean

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

test-integration: docker-build test-nft-real
	GOTUN_INTEGRATION=1 $(GO) test -tags=integration -count=1 -timeout 15m ./test/integration/...

test-large-set: docker-build
	GOTUN_LARGE_SET=1 $(GO) test -count=1 -timeout 20m ./internal/linux/nftables/ -run 'LargeRUSet'

docker-build:
	docker build -t gotun:lab .

fetch-prefixes: build
	@if [ -f "$(MMDB)" ]; then \
		$(BIN) fetch -mmdb "$(MMDB)" -out prefixes.txt; \
	else \
		echo "No local MMDB at $(MMDB); using MaxMind CSV download (MAXMIND_LICENSE_KEY required)"; \
		$(BIN) fetch -out prefixes.txt; \
	fi

clean:
	rm -rf bin/
