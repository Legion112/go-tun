GO ?= go
BIN := bin/gotun
BIN_DNS := bin/gotun-dns
BIN_CLIENT := bin/gotun-client
CLIENT_ARM64 := bin/gotun-client-linux-arm64
GOTUN_ARM64 := bin/gotun-linux-arm64
MMDB := data/geo/GeoIP2-City.mmdb

.PHONY: all build build-arm64 build-client-arm64 test test-integration test-large-set docker-build fetch-prefixes clean

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

test-integration: docker-build
	GOTUN_INTEGRATION=1 $(GO) test -tags=integration -count=1 -timeout 10m ./test/integration/...

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
