# The deploy lab: real OpenWrt with real procd as PID 1.
#
# This image exists to test a layer the Debian lab cannot reach -- procd
# supervision, the argv the init scripts build, config sourcing, rc.d ordering
# and file modes. It deliberately runs the same release as the router and the
# same nftables package, nftables-nojson, which is what exercises gotun's text
# nft readback path. That path is where the two-interface ingress-guard bug
# lived, and no other test in the tree touches it.
#
# Build with the repository root as the context:
#   docker build -t gotun:openwrt -f test/integration/openwrt/Dockerfile .

# The binaries come from the Debian lab image rather than being rebuilt, so
# both labs are guaranteed to exercise byte-identical binaries and this image
# costs no extra Go compilation. They are already CGO_ENABLED=0 static, so they
# run on musl unchanged.
FROM gotun:lab AS bin

FROM golang:1.26-bookworm AS logsink
WORKDIR /src
COPY go.mod go.sum ./
COPY test/integration/openwrt/logsink ./test/integration/openwrt/logsink
RUN CGO_ENABLED=0 go build -o /logsink ./test/integration/openwrt/logsink

# Pinned by digest: the x86-64-21.02.7 tag is mutable upstream, and a silent
# re-push would change what "the release the router runs" means in the middle of
# a refactor whose whole purpose is to not change behaviour.
FROM openwrt/rootfs:x86-64-21.02.7@sha256:7fc2353153c65d64a35a5fb4dc21a15bb048d812c19df3d8d4ea97745349ef79

# Packages must be installed here, at build time, and can never be installed at
# run time: netifd is disabled below, but before it was disabled it was observed
# enslaving the container's eth0 into br-lan, assigning 192.168.1.1/24 and
# taking the default route with it, which leaves the booted container with no
# network at all while `docker inspect` still reports an address.
#
# ip-full is not optional: busybox ip cannot do `ip link add type xfrm`, which
# is the one command gotun-ipsec.init exists to run. No kmod-* package belongs
# here -- those target this image's 5.4 kernel, while the real modules come from
# whatever kernel the host is running.
RUN mkdir -p /var/lock \
 && opkg update \
 && opkg install ip-full nftables-nojson wireguard-tools \
 && rm -rf /var/opkg-lists

# Neuter the parts of the stock boot that fight the container. Two of these are
# not tidiness, they are the difference between a usable lab and a hung one:
#
#   log      logd opens the kernel ring buffer and blocks reading it. In a
#            container that buffer is the host's and is quiet, so logd never
#            reaches its event loop and never accepts on /dev/log -- and then
#            every syslog writer blocks in connect(), procd included. A blocked
#            procd stops answering its ubus "service" object, so
#            `/etc/init.d/x start` hangs forever. Replaced by logsink below.
#   network  netifd, see above.
#
# The rest are noise or interference: firewall is fw3, whose iptables rules
# would sit alongside the nft table under test; sysntpd and ucitrack retry
# against a network that is deliberately absent. dnsmasq stays *installed* but
# does not start, because one scenario starts it deliberately to prove that
# gotun-dns does not collide with it on port 53.
RUN for svc in log network odhcpd firewall dnsmasq dropbear uhttpd ucitrack sysntpd cron; do \
        /etc/init.d/$svc disable 2>/dev/null || true; \
    done \
 && rm -f /etc/rc.d/*network /etc/rc.d/*odhcpd /etc/rc.d/*firewall \
          /etc/rc.d/*dnsmasq /etc/rc.d/*dropbear /etc/rc.d/*uhttpd \
          /etc/rc.d/*ucitrack /etc/rc.d/*sysntpd /etc/rc.d/*cron /etc/rc.d/*log

# Stop preinit from taking the container's network away. preinit puts a
# failsafe address on the LAN interface and then, in 99_10_run_init, calls
# preinit_ip_deconfig to flush it and set the device down before handing over
# to netifd. With netifd disabled nothing hands it back, so eth0 was observed
# left DOWN with no address and no default route -- while `docker inspect` still
# cheerfully reported the address it had assigned.
#
# pi_preinit_no_failsafe is OpenWrt's own knob for this: preinit_ip returns
# before setting pi_ifname, and both preinit_ip_deconfig and preinit_net_echo
# are guarded on pi_ifname being set, so they become no-ops while every function
# the other preinit hooks call stays defined. Patching or deleting the hook file
# would break those callers instead.
#
# The stderr suppression goes too, so that a preinit or procd failure is
# readable in `docker logs` rather than silent.
RUN sed -i \
        -e 's/^pi_preinit_no_failsafe=.*/pi_preinit_no_failsafe="y"/' \
        -e 's/^pi_suppress_stderr=.*/pi_suppress_stderr=""/' \
        -e 's/^pi_init_suppress_stderr=.*/pi_init_suppress_stderr=""/' \
        /lib/preinit/00_preinit.conf \
 && grep -E '^pi_(preinit_no_failsafe|suppress_stderr|init_suppress_stderr)=' \
        /lib/preinit/00_preinit.conf

COPY --from=bin /usr/local/bin/gotun     /usr/bin/gotun
COPY --from=bin /usr/local/bin/gotun-dns /usr/bin/gotun-dns
COPY --from=bin /usr/local/bin/labhttp   /usr/bin/labhttp
COPY --from=logsink /logsink             /usr/sbin/logsink

# Takes over /etc/init.d/log's START and STOP so the syslog socket appears at
# exactly the point in the boot order the stock image put it, before anything
# that logs has started.
RUN printf '%s\n' \
    '#!/bin/sh /etc/rc.common' \
    '# Stands in for logd, which cannot run in a container. See the Dockerfile.' \
    'START=12' \
    'STOP=89' \
    'USE_PROCD=1' \
    'start_service() {' \
    '    mkdir -p /var/log' \
    '    procd_open_instance' \
    '    procd_set_param command /usr/sbin/logsink' \
    '    procd_set_param respawn 5 1 -1' \
    '    procd_close_instance' \
    '}' \
    > /etc/init.d/logsink \
 && chmod 0755 /etc/init.d/logsink \
 && /etc/init.d/logsink enable

ENTRYPOINT ["/sbin/init"]
