package gotunclient

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_NoArgsPrintsUsage(t *testing.T) {
	var out bytes.Buffer
	err := Run(nil, &out)
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("err = %v", err)
	}
}

func TestRun_UnknownCommandErrors(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"frobnicate"}, &out); err == nil {
		t.Fatal("want error")
	}
}

func TestFlagPrefixes_ParsesRepeatable(t *testing.T) {
	var f flagPrefixes
	if err := f.Set("192.168.8.0/24"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set("10.99.99.0/30"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(f) != 2 || f.String() != "192.168.8.0/24,10.99.99.0/30" {
		t.Fatalf("got %q", f.String())
	}
}

// A bad CIDR must be rejected at flag-parse time, before anything is touched.
func TestFlagPrefixes_RejectsMalformed(t *testing.T) {
	var f flagPrefixes
	if err := f.Set("not-a-cidr"); err == nil {
		t.Fatal("want error")
	}
	if err := f.Set("192.168.8.1"); err == nil {
		t.Fatal("a bare address is not a prefix")
	}
	if err := f.Set("::ffff:10.0.0.0/104"); err == nil {
		t.Fatal("a 4-in-6 prefix should be rejected: it reads as IPv6 but denotes IPv4")
	}
}

// TestFlagPrefixes_AcceptsIPv6 is the inverse of what -lan used to enforce.
// Once the client points ::/0 at the gateway, an IPv6 LAN prefix needs
// protecting for exactly the reason an IPv4 one does.
func TestFlagPrefixes_AcceptsIPv6(t *testing.T) {
	var f flagPrefixes
	if err := f.Set("2001:db8::/32"); err != nil {
		t.Fatalf("IPv6 prefix rejected: %v", err)
	}
	if f[0].String() != "2001:db8::/32" {
		t.Fatalf("got %s", f[0])
	}
}

func TestFlagPrefixes_MasksHostBits(t *testing.T) {
	var f flagPrefixes
	if err := f.Set("192.168.8.99/24"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if f[0].String() != "192.168.8.0/24" {
		t.Fatalf("got %s, want masked", f[0])
	}
}

func TestParseAddrFlag(t *testing.T) {
	if _, err := parseAddrFlag("gateway", "192.168.8.162"); err != nil {
		t.Fatalf("valid address rejected: %v", err)
	}
	if _, err := parseAddrFlag("gateway", "nope"); err == nil {
		t.Fatal("want error")
	}
	// The family-neutral parser now accepts both; the flags that require one
	// enforce it themselves, so each states its own contract.
	if _, err := parseAddrFlag("ru-ip", "2001:db8::1"); err != nil {
		t.Fatalf("IPv6 rejected by the family-neutral parser: %v", err)
	}
}

func TestParseAddr4Flag_RejectsIPv6(t *testing.T) {
	if _, err := parseAddr4Flag("gateway", "2001:db8::1"); err == nil {
		t.Fatal("-gateway must stay IPv4; -gateway6 is the IPv6 one")
	}
	if _, err := parseAddr4Flag("gateway", "192.168.8.162"); err != nil {
		t.Fatalf("valid IPv4 rejected: %v", err)
	}
}

func TestParseAddr6Flag_RejectsIPv4(t *testing.T) {
	if _, err := parseAddr6Flag("gateway6", "192.168.8.162"); err == nil {
		t.Fatal("-gateway6 must be an IPv6 address")
	}
	if _, err := parseAddr6Flag("gateway6", "2001:db8::1"); err != nil {
		t.Fatalf("valid IPv6 rejected: %v", err)
	}
}

func TestRun_EnableRejectsBadFlags(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		{"enable", "-gateway", "bogus"},
		{"enable", "-lan", "bogus"},
		{"enable", "-apply-mode", "metric"},
	} {
		if err := Run(args, &out); err == nil {
			t.Errorf("%v should fail", args)
		}
	}
}
