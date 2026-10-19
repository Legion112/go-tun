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

// TestIKEv2Users_NamedCredentialsAreRevocable is the credential half of the
// IKEv2 transport: one named password per person, and a revocation that
// actually revokes.
//
// It is an integration test rather than a unit one for two reasons, both of
// which need a running daemon. Telling people apart is charon's job, not
// gotun's -- it reports the EAP identity of every SA next to the address it
// handed out, which is why nothing has to be pinned per user. And revoking is
// two steps: only a daemon can show that stopping the credential leaves an
// established tunnel up, because the connection does not reauthenticate and so
// rekeys without ever consulting the secret again.
func TestIKEv2Users_NamedCredentialsAreRevocable(t *testing.T) {
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

	// The shared half: one connection, one pool, the selectors. No credential.
	sharedFlags := []string{
		"-server", "vpn.lab",
		"-gateway-id", "vpn.lab",
		"-vip-subnet", ikev2VIPSubnet,
		"-vip-gateway", ikev2GatewayVIP,
		"-pool", ikev2PoolAddrs,
		"-probe-url", "http://vpn.lab:8443/alive",
		"-if-id", ikev2IfID,
	}
	base := append([]string{"gotun", "ikev2"}, sharedFlags...)
	if out, err := lab.Exec(ctx, "flint", append(base,
		"-out-swanctl", "/etc/swanctl/conf.d/gotun-ikev2.conf",
		"-out-profile", "/tmp/base.mobileconfig")...); err != nil {
		t.Fatalf("gotun ikev2: %v\n%s", err, out)
	}

	// Then the people. Users are added before charon starts, which is also the
	// realistic order: the snippets land in conf.d and the daemon picks them up
	// on load.
	secrets := map[string]string{}
	for _, name := range []string{"alice", "bob"} {
		// The subcommand comes before the flags, which is what gotun ikev2
		// now refuses to let you get wrong silently.
		args := append([]string{"gotun", "ikev2", "user", "add", name}, sharedFlags...)
		out, err := lab.Exec(ctx, "flint", append(args,
			"-dir", "/etc/swanctl/conf.d",
			"-out-profile", "/tmp/"+name+".mobileconfig",
			"-apply", "false")...)
		if err != nil {
			t.Fatalf("user add %s: %v\n%s", name, err, out)
		}
		secrets[name] = parsePassword(t, name, out)
	}

	// The password must not be anywhere a person could re-read it later, and
	// above all not in the file that gets copied to their phone. The per-user
	// file must be a credential and nothing else: a connection duplicated per
	// person would also duplicate the selector list, and two copies drift.
	for name, secret := range secrets {
		prof, err := lab.Exec(ctx, "flint", "cat", "/tmp/"+name+".mobileconfig")
		if err != nil {
			t.Fatalf("read %s's profile: %v", name, err)
		}
		if strings.Contains(prof, secret) {
			t.Errorf("%s's password is in their .mobileconfig", name)
		}
		snippet, err := lab.Exec(ctx, "flint", "cat",
			"/etc/swanctl/conf.d/gotun-user-"+name+".conf")
		if err != nil {
			t.Fatalf("read %s's snippet: %v", name, err)
		}
		for _, unwanted := range []string{"connections {", "local_ts"} {
			if strings.Contains(snippet, unwanted) {
				t.Errorf("%s's credential file contains %q, which is shared configuration",
					name, unwanted)
			}
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

	// 1: both are connected at the same time, through one shared connection.
	for _, name := range []string{"alice", "bob"} {
		waitIKESA(t, lab, name, 30*time.Second)
		if !reachable(t, lab, name, "http://"+ikev2GatewayVIP+":8080/id") {
			t.Fatalf("%s's tunnel does not carry traffic", name)
		}
	}

	// 2: the gateway can say who is who, and from which address, without any
	// per-user configuration. This is the answer to "do we need a fixed address
	// to attribute a session": no -- charon records the identity and the
	// address it handed out, together.
	raw, err := lab.Exec(ctx, "flint", "swanctl", "--list-sas", "--raw")
	if err != nil {
		t.Fatalf("list-sas --raw: %v", err)
	}
	ids := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		m := regexp.MustCompile(`remote-id=([a-z]+).*remote-vips=\[([^\]]*)\]`).FindStringSubmatch(line)
		if m != nil {
			ids[m[1]] = m[2]
		}
	}
	for _, name := range []string{"alice", "bob"} {
		if ids[name] == "" {
			t.Errorf("the gateway does not report %s's identity and address:\n%s", name, raw)
		}
	}
	if ids["alice"] == ids["bob"] && ids["alice"] != "" {
		t.Errorf("both users were handed the same address %q", ids["alice"])
	}

	// 3: and gotun surfaces it, so the operator does not have to read raw vici
	// output to find out who is on the tunnel.
	list, err := lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "list",
		"-dir", "/etc/swanctl/conf.d")
	if err != nil {
		t.Fatalf("user list: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if !strings.Contains(list, name) {
			t.Errorf("%s is missing from the listing:\n%s", name, list)
		}
	}
	for _, name := range []string{"alice", "bob"} {
		if !strings.Contains(list, ids[name]) {
			t.Errorf("the listing does not show %s's live address %s:\n%s", name, ids[name], list)
		}
	}

	// 4: a password is bound to its identity. Without this, one leaked
	// credential would be usable as anyone and per-user revocation would mean
	// nothing.
	writeEAPClient(t, lab, "bob", "alice", secrets["bob"], caPEM)
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--terminate", "--ike", "home"))
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--load-all"))
	_ = lab.ExecOK(ctx, "bob", "swanctl", "--initiate", "--child", "home")
	if reachable(t, lab, "bob", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("bob's password authenticated him as alice")
	}
	writeEAPClient(t, lab, "bob", "bob", secrets["bob"], caPEM)
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--load-all"))
	must(t, lab.ExecOK(ctx, "bob", "swanctl", "--initiate", "--child", "home"))
	waitIKESA(t, lab, "bob", 30*time.Second)

	// 5: the finding the revoke path is shaped around. Removing the credential
	// and reloading stops NEW sessions; the one alice already has keeps
	// working, because the connection does not reauthenticate.
	//
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

	// 6: ...and terminating by her identity is what ends it. This is the
	// mechanism gotun ikev2 user revoke uses: find the SA whose remote-id is
	// the user, terminate that unique id.
	aliceID := ""
	raw, err = lab.Exec(ctx, "flint", "swanctl", "--list-sas", "--raw")
	if err != nil {
		t.Fatalf("list-sas --raw: %v", err)
	}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, "remote-id=alice") {
			continue
		}
		if m := regexp.MustCompile(`uniqueid=([0-9]+)`).FindStringSubmatch(line); m != nil {
			aliceID = m[1]
		}
	}
	if aliceID == "" {
		t.Fatalf("could not find alice's session by identity:\n%s", raw)
	}
	must(t, lab.ExecOK(ctx, "flint", "swanctl", "--terminate", "--ike-id", aliceID))
	if reachable(t, lab, "alice", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("alice's session survived the terminate")
	}
	_ = lab.ExecOK(ctx, "alice", "swanctl", "--initiate", "--child", "home")
	if reachable(t, lab, "alice", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("a revoked user reconnected")
	}

	// 7: revocation is per person. bob was never touched and must be
	// unaffected -- a revocation that takes everyone down with it is not one
	// you would dare use.
	if !reachable(t, lab, "bob", "http://"+ikev2GatewayVIP+":8080/id") {
		t.Error("revoking alice disturbed bob")
	}
	if list, err := lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "list",
		"-dir", "/etc/swanctl/conf.d"); err != nil {
		t.Fatalf("user list: %v", err)
	} else if strings.Contains(list, "alice") {
		t.Errorf("alice is still listed after revocation:\n%s", list)
	}

	// 8: and the applied form does both steps in one command, which is the form
	// an operator will actually use under pressure.
	out, err = lab.Exec(ctx, "flint", "gotun", "ikev2", "user", "revoke", "bob",
		"-dir", "/etc/swanctl/conf.d")
	if err != nil {
		t.Fatalf("revoke bob: %v\n%s", err, out)
	}
	if !strings.Contains(out, "terminated bob's session") {
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
