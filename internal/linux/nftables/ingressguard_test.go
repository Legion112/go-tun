package nftables

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// Both readback paths must find every interface named in the ingress guard.
//
// Pinned at one interface and at two because the two sizes do not render the
// same: nft normalizes a one-element anonymous set back to a bare string and
// keeps the set form from two elements up. So the single-interface case
// round-tripped cleanly through the JSON parser while the two-interface case
// found no names at all -- the guard never matched the spec, and reconciliation
// being delete-and-rewrite, the entire table was rebuilt on every apply.
//
// Two interfaces is a LAN bridge plus a phone's tunnel device, which is what
// -clients-iface exists for. Every test in this package classified exactly one
// until now, which is why the bug was invisible.
func TestIngressGuard_BothParsersFindEveryInterface(t *testing.T) {
	cases := []struct {
		name string
		js   string
		text string
		want []string
	}{
		{
			name: "one interface: nft normalizes the set to a bare string",
			js:   `{"chain":"prerouting","comment":"only-marked-ingress","expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"br-lan"}},{"return":null}]}`,
			text: `iifname != "br-lan" return comment "only-marked-ingress"`,
			want: []string{"br-lan"},
		},
		{
			name: "two interfaces: nft keeps the anonymous set",
			js:   `{"chain":"prerouting","comment":"only-marked-ingress","expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":{"set":["br-lan","ipsec0"]}}},{"return":null}]}`,
			text: `iifname != { "br-lan", "ipsec0" } return comment "only-marked-ingress"`,
			want: []string{"br-lan", "ipsec0"},
		},
		{
			name: "three interfaces, which is br-lan plus a phone plus a guest bridge",
			js:   `{"chain":"prerouting","comment":"only-marked-ingress","expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":{"set":["br-guest","br-lan","ipsec0"]}}},{"return":null}]}`,
			text: `iifname != { "br-guest", "br-lan", "ipsec0" } return comment "only-marked-ingress"`,
			want: []string{"br-guest", "br-lan", "ipsec0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fromJSON, ok := parseRuleJSON(json.RawMessage(tc.js))
			if !ok {
				t.Fatalf("JSON rule did not parse: %s", tc.js)
			}
			if got := sorted(fromJSON.IIfNames); !equalStrings(got, tc.want) {
				t.Errorf("JSON path: got %v want %v", got, tc.want)
			}

			fromText := parseRuleText("prerouting", tc.text)
			if got := sorted(fromText.IIfNames); !equalStrings(got, tc.want) {
				t.Errorf("text path: got %v want %v", got, tc.want)
			}
		})
	}
}

// The guard is the only braced match the renderer emits, so a set on the right
// of a meta match is always interface names. Anything else there is not ours
// and must not be mistaken for one.
func TestIngressGuard_NonStringSetIsNotAnInterface(t *testing.T) {
	js := `{"chain":"prerouting","comment":"x","expr":[{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":{"set":[{"prefix":{"addr":"10.0.0.0","len":8}}]}}}]}`
	r, ok := parseRuleJSON(json.RawMessage(js))
	if !ok {
		t.Fatalf("rule did not parse")
	}
	if len(r.IIfNames) != 0 {
		t.Errorf("want no interface names, got %v", r.IIfNames)
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	return len(a) == len(b) && strings.Join(a, ",") == strings.Join(b, ",")
}
