package nftables

import "github.com/legion/go-tun/internal/policy"

// l3 is the nft payload keyword for a family: "ip daddr" versus "ip6 daddr".
//
// In an inet table each keyword carries an implicit nfproto dependency, so a v6
// packet simply does not match an "ip daddr" rule and vice versa. That is what
// lets both families share one chain without guarding every rule by hand.
func l3(f policy.Family) string {
	if f == policy.FamilyV6 {
		return "ip6"
	}
	return "ip"
}

// nfproto is the nft meta nfproto value for a family.
func nfproto(f policy.Family) string {
	if f == policy.FamilyV6 {
		return "ipv6"
	}
	return "ipv4"
}

// RuleComment is the comment a rule carries in the live table.
//
// The family is part of the comment, and that is a load-bearing design choice
// rather than cosmetics. Readback buckets rules by comment, and the text parser
// -- the one the router uses, because OpenWrt ships nftables without JSON --
// cannot tell "ip daddr" from "ip6 daddr": it keys on the bare daddr token. If
// both families shared a comment, their destination lists would merge into one
// bucket on the text path and stay separate on the JSON path, so the same live
// table would read as converged on one box and as permanent drift on the other.
// Drift here is not cosmetic either: reconciliation is delete-and-rewrite, so
// the whole table, all ~17k elements of it, would be rebuilt on every apply.
//
// Both the renderer and the matcher call this, so they cannot disagree. Do not
// reuse a comment across families.
func RuleComment(description string, f policy.Family) string {
	if f == policy.FamilyV6 {
		return description + "-v6"
	}
	return description
}
