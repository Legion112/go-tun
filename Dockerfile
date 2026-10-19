FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN CGO_ENABLED=0 go build -o /gotun ./cmd/gotun \
 && CGO_ENABLED=0 go build -o /gotun-dns ./cmd/gotun-dns \
 && CGO_ENABLED=0 go build -o /labhttp ./cmd/labhttp \
 && CGO_ENABLED=0 go build -o /labdns ./cmd/labdns

FROM debian:bookworm-slim
# strongswan is here for the IKEv2 phone lab. The package split is not obvious
# and the wrong guess installs a strongswan with no daemon in it:
#   strongswan-charon          the charon daemon and the vici plugin swanctl talks to
#   strongswan-swanctl         swanctl itself and /etc/swanctl
#   libcharon-extauth-plugins  eap-mschapv2, which is the auth an iPhone profile ships
#   strongswan-pki             mints the throwaway server certificate
#   libstrongswan-standard-plugins  openssl, and with it GCM and the ECP curves
# The last one is the trap: without it charon starts, loads, and then has no
# cipher for any modern proposal, so negotiation fails as "no proposal chosen"
# rather than as a missing package. strongswan-starter arrives as a dependency
# of strongswan-charon and is unused here -- the lab is swanctl-only.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables wireguard-tools iproute2 iputils-ping curl ca-certificates \
    procps dnsutils \
    strongswan-charon strongswan-swanctl strongswan-pki \
    libstrongswan-standard-plugins \
    libcharon-extauth-plugins \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /gotun /usr/local/bin/gotun
COPY --from=build /gotun-dns /usr/local/bin/gotun-dns
COPY --from=build /labhttp /usr/local/bin/labhttp
COPY --from=build /labdns /usr/local/bin/labdns
ENTRYPOINT ["sleep", "infinity"]
