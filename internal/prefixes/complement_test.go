package prefixes_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

func rangeStrings(rs []prefixes.Range) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// The claim the whole IKEv2 traffic-selector design rests on: "everything
// except private and reserved space" is a seven-entry list.
//
// Pinned exactly, because the number is the argument. As prefixes the same set
// is ~35 entries, and iOS publishes no limit on how many selectors it accepts,
// so the difference is between a proposal that obviously works and one whose
// failure mode is discovered on a phone.
//
// Reserved space has to be cut alongside the non-routable list. 0.0.0.0/8 and
// 240.0.0.0/4 are not in DefaultNonRoutable -- they never needed to be, since
// nothing on a LAN is addressed there -- but leaving them in makes the
// complement advertise two ranges no packet will ever use.
func TestComplement_PrivateAndReservedIsSevenV4Ranges(t *testing.T) {
	cut := append(policy.DefaultNonRoutable(),
		mustPrefixes(t, "0.0.0.0/8", "240.0.0.0/4")...)

	got := rangeStrings(prefixes.Complement(cut, prefixes.Families{V4: true}))
	want := []string{
		"1.0.0.0-9.255.255.255",
		"11.0.0.0-100.63.255.255",
		"100.128.0.0-126.255.255.255",
		"128.0.0.0-169.253.255.255",
		"169.255.0.0-172.15.255.255",
		"172.32.0.0-192.167.255.255",
		"192.169.0.0-223.255.255.255",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("complement of private+reserved v4:\n got %v\nwant %v", got, want)
	}
}

// Without cutting reserved space the list grows by exactly one range and the
// first one starts two addresses lower, which is the evidence for the test
// above rather than a separate behaviour. 0.0.0.0/8 does not add a range -- it
// only trims the front of the first one -- so the cost of leaving reserved
// space in is one dead selector, not two.
func TestComplement_LeavingReservedInAddsOneDeadRange(t *testing.T) {
	got := rangeStrings(prefixes.Complement(policy.DefaultNonRoutable(), prefixes.Families{V4: true}))
	if len(got) != 8 {
		t.Fatalf("want 8 ranges without the reserved cut, got %d: %v", len(got), got)
	}
	if got[0] != "0.0.0.0-9.255.255.255" {
		t.Errorf("first range should start at 0.0.0.0, got %q", got[0])
	}
	if last := got[len(got)-1]; last != "240.0.0.0-255.255.255.255" {
		t.Errorf("last range should be the dead reserved block, got %q", last)
	}
}

// The gateway's own tunnel-side address lives inside RFC1918, so the list that
// keeps the client's local LAN off the tunnel also cuts the address gotun-dns
// listens on. Subtracting the exception from the cut has to produce one
// contiguous pair of ranges around it; composing two complement results
// afterwards would leave an unmerged seam instead.
func TestSubtract_PunchesTheVIPSubnetBackIn(t *testing.T) {
	got := rangeStrings(prefixes.Subtract(
		mustPrefixes(t, "10.231.0.0/16"),
		mustPrefixes(t, "10.231.17.0/24"),
	))
	want := []string{
		"10.231.0.0-10.231.16.255",
		"10.231.18.0-10.231.255.255",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("subtract:\n got %v\nwant %v", got, want)
	}
}

// Cutting the VIP subnet out of the exclusion list before complementing is the
// composition the IKEv2 generator performs. The result must contain the VIP
// subnet, or the phone sends DNS to whatever resolver the network it is sitting
// on advertises -- a working tunnel with silently wrong GeoDNS answers.
func TestComplement_VIPSubnetSurvivesTheExclusionList(t *testing.T) {
	vip := netip.MustParsePrefix("10.231.17.0/24")
	cut := prefixes.RangePrefixes(prefixes.Subtract(
		policy.DefaultNonRoutable(),
		[]netip.Prefix{vip},
	))

	selectors := prefixes.Complement(cut, prefixes.Families{V4: true})
	vipEnd := netip.MustParseAddr("10.231.17.255")
	var covered bool
	for _, r := range selectors {
		if !vip.Addr().Less(r.From) && !r.To.Less(vipEnd) {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("no selector covers the VIP subnet %s: %v", vip, rangeStrings(selectors))
	}
}

func TestComplement_EmptyCutIsTheWholeFamily(t *testing.T) {
	got := rangeStrings(prefixes.Complement(nil, prefixes.Families{V4: true}))
	want := []string{"0.0.0.0-255.255.255.255"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestComplement_FullCutIsEmpty(t *testing.T) {
	got := prefixes.Complement(mustPrefixes(t, "0.0.0.0/0"), prefixes.Families{V4: true})
	if got != nil {
		t.Fatalf("want no ranges, got %v", rangeStrings(got))
	}
}

// The top of the address space is where an off-by-one lives: Addr.Next returns
// an invalid address there rather than wrapping, and treating that as a usable
// cursor would emit a range running backwards from 0.0.0.0.
func TestComplement_CutAtTheTopOfTheSpace(t *testing.T) {
	got := rangeStrings(prefixes.Complement(mustPrefixes(t, "255.255.255.0/24"), prefixes.Families{V4: true}))
	want := []string{"0.0.0.0-255.255.254.255"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestComplement_IPv6PrivateSpace(t *testing.T) {
	got := rangeStrings(prefixes.Complement(policy.DefaultNonRoutable(), prefixes.Families{V6: true}))
	want := []string{
		"::-::",
		"::2-fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fe00::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("complement of private v6:\n got %v\nwant %v", got, want)
	}
}

// Both families in one call, because the IKEv2 proposal carries both and a
// generator that silently emitted only one would leave the phone's IPv6 on the
// carrier -- the leak that matters most on a cellular network.
func TestComplement_BothFamiliesInOneCall(t *testing.T) {
	got := prefixes.Complement(policy.DefaultNonRoutable(), prefixes.Families{V4: true, V6: true})
	var v4, v6 int
	for _, r := range got {
		if r.From.Is4() {
			v4++
		} else {
			v6++
		}
	}
	if v4 == 0 || v6 == 0 {
		t.Fatalf("want both families, got v4=%d v6=%d: %v", v4, v6, rangeStrings(got))
	}
}

// The wire form and the kernel form must describe the same addresses.
// Prefixes is what builds XFRM policies and routes; the range is what goes
// into swanctl. A decomposition that drifted would be a split tunnel that
// works on the gateway and not on the client.
func TestRange_PrefixesCoverExactlyTheRange(t *testing.T) {
	for _, r := range prefixes.Complement(policy.DefaultNonRoutable(), prefixes.Families{V4: true, V6: true}) {
		ps := r.Prefixes()
		if len(ps) == 0 {
			t.Fatalf("%s decomposed to nothing", r)
		}
		if got := ps[0].Masked().Addr(); got != r.From {
			t.Errorf("%s: first prefix starts at %s, want %s", r, got, r.From)
		}
		// Contiguous, non-overlapping, and ending exactly on r.To -- the three
		// properties together are what "covers exactly" means.
		for i, p := range ps {
			if p.Masked() != p {
				t.Fatalf("%s: prefix %s is not canonical", r, p)
			}
			if i == 0 {
				continue
			}
			want := lastAddrOf(ps[i-1]).Next()
			if p.Addr() != want {
				t.Fatalf("%s: prefix %s does not follow %s (expected to start at %s)",
					r, p, ps[i-1], want)
			}
		}
		if got := lastAddrOf(ps[len(ps)-1]); got != r.To {
			t.Errorf("%s: decomposition ends at %s", r, got)
		}
	}
}

// lastAddrOf duplicates the package-private helper on purpose: a test that
// reused it would pass even if both it and the decomposition were wrong in the
// same direction.
func lastAddrOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= p.Bits() {
				b[i] |= 1 << (7 - bit)
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
