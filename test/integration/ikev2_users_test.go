//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

// TestIKEv2Users_NamedCredentialsAreFixedAndRevocable is the credential half of
// the IKEv2 transport: one named password per person, a fixed address each, and
// a revocation that actually revokes.
//
// The last part is why this is an integration test rather than a unit one.
// Revoking is two steps -- stop accepting the credential, and tear down the
// session already using it -- and only a running daemon can show that the first
// step alone leaves the tunnel up. The generated connection does not
// reauthenticate, so an established IKE_SA rekeys without ever consulting the
// secret again.
func TestIKEv2Users_NamedCredentialsAreFixedAndRevocable(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotunusers%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "inet", "10.40.0.0/24"))
	must(t, lab.RunContainer(ctx, "flint", image, "10.40.0.2", "inet", nil))
	must(t, lab.RunContainer(ctx, "alice", image, "10.40.0.10", "inet", nil))
	must(t, lab.RunContainer(ctx, "bob", image, "10.40.0.11", "inet", nil))
	for _, n := range []string{"flint", "alice", "bob"} {
		must(t, lab.WaitReady(ctx, n))
	}
	requireXfrmInterface(t, lab, "flint")

	wanIface := ifaceForAddr(t, lab, "flint", "10.40.0.2")
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
ip link add %[1]s type xfrm dev %[2]s if_id %[3]s
ip link set %[1]s up
ip address replace %[4]s/24 dev %[1]s
labhttp -listen %[4]s:8080 -body GATEWAY >/tmp/vip-http.log 2>&1 &
`, ikev2ClientsIface, wanIface, ikev2IfID, ikev2GatewayVIP)))

	// The certificate path the shipping profile uses: the gateway proves itself
	// with a certificate, each person with their own password.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", `
set -e
pki --gen --type ecdsa --size 256 --outform pem > /etc/swanctl/private/ca.key
pki --self --ca --in /etc/swanctl/private/ca.key --type ecdsa --dn "CN=gotun-lab-ca" \
  --outform pem > /etc/swanctl/x509ca/ca.pem
pki --gen --type ecdsa --size 256 --outform pem > /etc/swanctl/private/gw.key
pki --pub --in /etc/swanctl/private/gw.key --type ecdsa \
  | pki --issue --cacert /etc/swanctl/x509ca/ca.pem --cakey /etc/swanctl/private/ca.key \
      --dn "CN=vpn.lab" --san vpn.lab --flag serverAuth --outform pem > /etc/swanctl/x509/gotun-gw.pem
`))

	// Users are added before charon starts, which is also the realistic order:
	// the snippets land in conf.d and the daemon picks them up on load.
	secrets := map[string]string{}
	for _, name := range []string{"alice", "bob"} {
		out, err := lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "add", name,
			"-server", "vpn.lab",
			"-gateway-id", "vpn.lab",
			"-vip-subnet", ikev2VIPSubnet,
			"-vip-gateway", ikev2GatewayVIP,
			"-pool", ikev2PoolAddrs,
			"-probe-url", "http://vpn.lab:8443/alive",
			"-if-id", ikev2IfID,
			"-dir", "/etc/swanctl/conf.d",
			"-out-profile", "/tmp/"+name+".mobileconfig",
			"-apply", "false",
		)
		if err != nil {
			t.Fatalf("user add %s: %v\n%s", name, err, out)
		}
		secrets[name] = parsePassword(t, name, out)
	}

	// The password must not be anywhere a person could re-read it later, and
	// above all not in the file that gets copied to their phone.
	for name, secret := range secrets {
		prof, err := lab.Exec(ctx, "flint", "cat", "/tmp/"+name+".mobileconfig")
		if err != nil {
			t.Fatalf("read %s's profile: %v", name, err)
		}
		if strings.Contains(prof, secret) {
			t.Errorf("%s's password is in their .mobileconfig", name)
		}
		mode, err := lab.Exec(ctx, "flint", "stat", "-c", "%a",
			"/etc/swanctl/conf.d/gotun-user-"+name+".conf")
		if err != nil || strings.TrimSpace(mode) != "600" {
			t.Errorf("%s's snippet mode is %q, want 600 (%v)", name, strings.TrimSpace(mode), err)
		}
	}

	startCharon(t, lab, "flint")

	// Each client is its own person: its own identity, its own password.
	caPEM, err := lab.Exec(ctx, "flint", "cat", "/etc/swanctl/x509ca/ca.pem")
	if err != nil {
		t.Fatalf("read the CA: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		writeEAPClient(t, lab, name, name, secrets[name], caPEM)
		startCharon(t, lab, name)
		must(t, lab.ExecOK(ctx, name, "swanctl", "--initiate", "--child", "home"))
	}

	// --- assertions ---

	// 1: both are connected at the same time, each with the address their file
	// pins. Read at the destination rather than from the client, so it is the
	// address traffic actually arrives from.
	want := map[string]string{"alice": "10.231.17.17", "bob": "10.231.17.18"}
	for _, name := range []string{"alice", "bob"} {
		waitIKESA(t, lab, name, 30*time.Second)
		got := mustGet(t, lab, name, "http://"+ikev2GatewayVIP+":8080/peer")
		if got != want[name] {
			t.Errorf("%s arrives from %q, want %q", name, got, want[name])
		}
	}

	// 2: the gateway can say who is who. Attribution is the reason the
	// addresses are fixed at all, and it comes from the connection being named
	// after the user.
	sas, err := lab.Exec(ctx, "flint", "swanctl", "--list-sas")
	if err != nil {
		t.Fatalf("list-sas: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if !strings.Contains(sas, name+":") {
			t.Errorf("the gateway does not name %s's SA:\n%s", name, sas)
		}
	}

	// 3: the address survives a reconnect. A sticky lease would pass the first
	// assertion and fail this one.
	must(t, lab.ExecOK(ctx, "alice", "swanctl", "--terminate", "--ike", "home"))
	time.Sleep(time.Second)
	must(t, lab.ExecOK(ctx, "alice", "swanctl", "--initiate", "--child", "home"))
	waitIKESA(t, lab, "alice", 30*time.Second)
	if got := mustGet(t, lab, "alice", "http://"+ikev2GatewayVIP+":8080/peer"); got != want["alice"] {
		t.Errorf("after reconnecting alice arrives from %q, want %q", got, want["alice"])
	}

	// 4: a password is bound to its identity. Without this, one leaked
	// credential would be usable as anyone, and per-user revocation would mean
	// nothing.
	writeEAPClient(t, lab, "bob", "alice", secrets["bob"], caPEM)
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--terminate", "--ike", "home"))
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--load-all"))
	_ = lab.ExecOK(ctx, "bob", "swanctl", "--initiate", "--child", "home")
	if reachable(t, lab, "bob", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("bob's password authenticated him as alice")
	}
	// Put bob back as himself.
	writeEAPClient(t, lab, "bob", "bob", secrets["bob"], caPEM)
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--load-all"))
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--initiate", "--child", "home"))
	waitIKESA(t, lab, "bob", 30*time.Second)

	// 5: the finding this whole procedure is shaped around. Removing the
	// credential and reloading stops NEW sessions; the one alice already has
	// keeps working, because the connection does not reauthenticate.
	// Through a shell with stderr folded in: the warning is deliberately on
	// stderr, and harness.Exec returns only stdout on success.
	out, err := lab.Exec(ctx, "flint", "bash", "-c",
		"gotun ikev2 user revoke alice -dir /etc/swanctl/conf.d -apply false 2>&1")
	if err != nil {
		t.Fatalf("revoke alice: %v\n%s", err, out)
	}
	if !strings.Contains(out, "NOT APPLIED") {
		t.Errorf("a revoke that was not applied must say so loudly, got:\n%s", out)
	}
	must(t, lab.ExecOK(ctx, "flint", "swanctl", "--load-all"))
	if !reachable(t, lab, "alice", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("alice's established session should have survived the reload -- if this ever" +
			" starts passing, the two-step revocation is no longer necessary and the docs" +
			" and gotun ikev2 user revoke should both be revisited")
	}

	// 6: ...and the second step is what actually ends it.
	if _, err := lab.Exec(ctx, "flint", "swanctl", "--terminate", "--ike", "alice"); err != nil {
		t.Fatalf("terminate alice: %v", err)
	}
	if reachable(t, lab, "alice", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("alice's session survived the terminate")
	}
	// And she cannot come back.
	_ = lab.ExecOK(ctx, "alice", "swanctl", "--initiate", "--child", "home")
	if reachable(t, lab, "alice", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("a revoked user reconnected")
	}

	// 7: revocation is per user. bob was never touched and must be unaffected
	// throughout -- a revocation that takes everyone down with it is not one
	// you would dare use.
	if !reachable(t, lab, "bob", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("revoking alice disturbed bob")
	}
	if got := mustGet(t, lab, "bob", "http://"+ikev2GatewayVIP+":8080/peer"); got != want["bob"] {
		t.Errorf("bob's address moved to %q after alice was revoked", got)
	}

	// 8: the revoked name holds its address, so the next person cannot inherit
	// alice's history.
	list, err := lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "list", "-dir", "/etc/swanctl/conf.d")
	if err != nil {
		t.Fatalf("user list: %v", err)
	}
	if !strings.Contains(list, "bob") || !strings.Contains(list, "active") {
		t.Errorf("bob should still be listed as active:\n%s", list)
	}
	if !strings.Contains(list, "revoked") || !strings.Contains(list, want["alice"]) {
		t.Errorf("alice should be listed as revoked, still holding %s:\n%s", want["alice"], list)
	}
	add, err := lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "add", "carol",
		"-server", "vpn.lab", "-gateway-id", "vpn.lab",
		"-vip-subnet", ikev2VIPSubnet, "-vip-gateway", ikev2GatewayVIP, "-pool", ikev2PoolAddrs,
		"-probe-url", "http://vpn.lab:8443/alive", "-if-id", ikev2IfID,
		"-dir", "/etc/swanctl/conf.d", "-out-profile", "/tmp/carol.mobileconfig", "-apply", "false")
	if err != nil {
		t.Fatalf("user add carol: %v\n%s", err, add)
	}
	if strings.Contains(add, want["alice"]) {
		t.Errorf("carol was handed alice's revoked address:\n%s", add)
	}

	// 9: the applied path ends a session without a separate command, which is
	// the form an operator will actually use under pressure.
	out, err = lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "revoke", "bob",
		"-dir", "/etc/swanctl/conf.d")
	if err != nil {
		t.Fatalf("revoke bob: %v\n%s", err, out)
	}
	if !strings.Contains(out, "terminated bob's live session") {
		t.Errorf("an applied revoke should report the teardown, got:\n%s", out)
	}
	if reachable(t, lab, "bob", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("bob's session survived an applied revoke")
	}
}

var passwordLine = regexp.MustCompile(`password for ([a-z0-9._-]+):\s+(\S+)`)

func parsePassword(t *testing.T, name, out string) string {
	t.Helper()
	for _, m := range passwordLine.FindAllStringSubmatch(out, -1) {
		if m[1] == name {
			return m[2]
		}
	}
	t.Fatalf("no password for %s in:\n%s", name, out)
	return ""
}

// writeEAPClient configures one road-warrior client: its own identity, its own
// password, and the gateway's CA so it can authenticate the server.
//
// identity is separate from the container name so a test can offer one person's
// password under another's name.
func writeEAPClient(t *testing.T, lab *harness.Lab, container, identity, secret, caPEM string) {
	t.Helper()
	ctx := context.Background()
	conf := fmt.Sprintf(`connections {
  home {
    version = 2
    remote_addrs = 10.40.0.2
    vips = 0.0.0.0
    encap = yes
    local-1 {
      auth = eap
      id = %s
    }
    remote-1 {
      auth = pubkey
      id = vpn.lab
    }
    children {
      home {
        remote_ts = 0.0.0.0/0
        start_action = none
      }
    }
  }
}
secrets {
  eap-%s {
    id = %s
    secret = "%s"
  }
}
`, identity, identity, identity, secret)
	writeSwanctlConf(t, lab, container, conf)
	must(t, lab.ExecOK(ctx, container, "bash", "-c",
		fmt.Sprintf("cat > /etc/swanctl/x509ca/ca.pem <<'PEM'\n%s\nPEM", strings.TrimSpace(caPEM))))
}

// reachable reports whether the client can still use its tunnel. Used for both
// outcomes, so the negative assertions cannot be satisfied by a transport error
// that would also break the positive ones.
func reachable(t *testing.T, lab *harness.Lab, container, url string) bool {
	t.Helper()
	out, err := lab.Exec(context.Background(), container, "curl", "-s", "--max-time", "4", url)
	return err == nil && strings.TrimSpace(out) == "GATEWAY"
}
