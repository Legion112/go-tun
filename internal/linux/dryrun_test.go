package linux_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
)

// Classification is allow-list, so anything unrecognised must be withheld. A
// deny-list would let a "dry run" change a household router's forwarding.
func TestDryRunner_UnknownCommandIsWithheld(t *testing.T) {
	inner := linux.NewRecordingRunner()
	var out bytes.Buffer
	d := &linux.DryRunner{Inner: inner, Out: &out}

	if _, err := d.Run("iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"); err != nil {
		t.Fatal(err)
	}
	if len(inner.Calls) != 0 {
		t.Fatalf("an unrecognised command must not reach the host: %v", inner.Calls)
	}
	if !strings.Contains(out.String(), "DRY-RUN: iptables") {
		t.Fatalf("expected it to be printed, got %q", out.String())
	}
}

func TestDryRunner_ReadsReachTheHost(t *testing.T) {
	inner := linux.NewRecordingRunner()
	var out bytes.Buffer
	d := &linux.DryRunner{Inner: inner, Out: &out}

	for _, c := range [][]string{
		{"nft", "-j", "list", "table", "inet", "gotun"},
		{"nft", "list", "table", "inet", "gotun"},
		{"ip", "route", "show", "table", "100"},
		{"ip", "rule", "show"},
		{"ip", "link", "show", "dev", "wg-exit"},
		{"wg", "show", "wg-exit", "dump"},
		{"sysctl", "-n", "net.ipv4.ip_forward"},
		{"sh", "-c", "cat /proc/sys/net/ipv4/ip_forward"},
	} {
		if _, err := d.Run(c[0], c[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	if len(inner.Calls) != 8 {
		t.Fatalf("all 8 reads should reach the host, got %d: %v", len(inner.Calls), inner.Calls)
	}
	if out.Len() != 0 {
		t.Fatalf("a read must print nothing, got %q", out.String())
	}
}

func TestDryRunner_WritesAreWithheld(t *testing.T) {
	inner := linux.NewRecordingRunner()
	var out bytes.Buffer
	d := &linux.DryRunner{Inner: inner, Out: &out}

	for _, c := range [][]string{
		{"nft", "-f", "/proc/self/fd/0"},
		{"nft", "delete", "table", "inet", "gotun"},
		{"ip", "route", "replace", "default", "dev", "wg-exit", "table", "100"},
		{"ip", "route", "flush", "table", "100"},
		{"ip", "rule", "add", "priority", "100", "fwmark", "0x1", "lookup", "100"},
		{"ip", "link", "set", "dev", "wg-exit", "up"},
		{"wg", "set", "wg-exit", "private-key", "/proc/self/fd/0"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"sh", "-c", "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects"},
	} {
		if _, err := d.Run(c[0], c[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	if len(inner.Calls) != 0 {
		t.Fatalf("no write may reach the host: %v", inner.Calls)
	}
	if d.Writes != 9 {
		t.Fatalf("want 9 withheld writes, got %d", d.Writes)
	}
}

// A dry run of an nft batch is only useful if the batch itself is shown.
func TestDryRunner_PipedScriptIsPrinted(t *testing.T) {
	inner := linux.NewRecordingRunner()
	var out bytes.Buffer
	d := &linux.DryRunner{Inner: inner, Out: &out}

	if _, err := d.RunWithInput("nft", "delete table inet gotun\nadd table inet gotun\n", "-f", linux.StdinPath); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"delete table inet gotun", "add table inet gotun"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the batch should be shown, %q missing from:\n%s", want, out.String())
		}
	}
}
