package ikev2_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/ikev2"
	"gopkg.in/yaml.v3"
	"howett.net/plist"
)

// Apple publishes a machine-readable schema for every configuration payload.
// This checks the profile against it: every key emitted must exist in the
// schema, at the depth it is emitted.
//
// Depth is the point. The bug this package shipped was not a typo and not a
// wrong type -- it was the DNS dictionary nested one level too deep, inside
// IKEv2 rather than beside it. iOS ignores an unknown key in silence, so the
// profile installed cleanly, looked right and changed nothing; it took
// measuring a live phone to find. Line coverage of the code that wrote it was
// 100%, and a typed struct would have serialised the wrong shape just as
// happily. A schema the vendor publishes is the only thing here that knows
// where a key belongs.
//
// The schemas are vendored rather than fetched, so the test is hermetic and
// so that updating them is a visible change in a diff.

type schemaKey struct {
	Key     string      `yaml:"key"`
	Type    string      `yaml:"type"`
	Subkeys []schemaKey `yaml:"subkeys"`
}

type payloadSchema struct {
	Payload struct {
		PayloadType string `yaml:"payloadtype"`
	} `yaml:"payload"`
	PayloadKeys []schemaKey `yaml:"payloadkeys"`
}

// commonPayloadKeys are the keys every payload carries. Apple schemas them
// once, elsewhere, rather than repeating them in each payload file, so they
// would otherwise read as unknown.
var commonPayloadKeys = map[string]bool{
	"PayloadType": true, "PayloadVersion": true, "PayloadIdentifier": true,
	"PayloadUUID": true, "PayloadDisplayName": true, "PayloadDescription": true,
	"PayloadOrganization": true, "PayloadRemovalDisallowed": true,
	"PayloadContent": true, "PayloadCertificateFileName": true,
}

func loadSchemas(t *testing.T) map[string]payloadSchema {
	t.Helper()
	out := map[string]payloadSchema{}
	dir := filepath.Join("testdata", "schema")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var s payloadSchema
		if err := yaml.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if s.Payload.PayloadType == "" {
			t.Fatalf("%s declares no payloadtype", e.Name())
		}
		out[s.Payload.PayloadType] = s
	}
	if len(out) == 0 {
		t.Fatal("no schemas vendored under testdata/schema")
	}
	return out
}

func TestProfile_ConformsToApplesPublishedSchema(t *testing.T) {
	schemas := loadSchemas(t)

	// The full matrix, because an unknown key is only emitted under the
	// options that produce it -- the DNS dictionary did not exist at all
	// until a flag turned it on.
	caPEM := goldenCA(t)
	cases := map[string]func(*ikev2.Config){
		"minimal":       func(*ikev2.Config) {},
		"with-ca":       func(c *ikev2.Config) { c.CAPEM = caPEM },
		"on-demand-off": func(c *ikev2.Config) { c.OnDemandDisabled = true },
		"dns-all":       func(c *ikev2.Config) { c.DNSMatchDomains = []string{""} },
		"dns-domains":   func(c *ikev2.Config) { c.DNSMatchDomains = []string{"ru"} },
		"production": func(c *ikev2.Config) {
			c.CAPEM = caPEM
			c.DNSMatchDomains = []string{""}
			c.HomeSSIDs = []string{"Home"}
			c.ProbeURL = "http://vpn.example.net:8443/alive"
		},
	}

	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := goldenConfig()
			mut(&c)
			raw, err := ikev2.EncodeProfile(c)
			if err != nil {
				t.Fatal(err)
			}

			var profile struct {
				PayloadContent []map[string]any `plist:"PayloadContent"`
			}
			if _, err := plist.Unmarshal(raw, &profile); err != nil {
				t.Fatalf("the profile is not valid plist: %v", err)
			}
			if len(profile.PayloadContent) == 0 {
				t.Fatal("no payloads")
			}

			for _, payload := range profile.PayloadContent {
				pt, _ := payload["PayloadType"].(string)
				s, ok := schemas[pt]
				if !ok {
					t.Fatalf("no vendored schema for payload type %q", pt)
				}
				var problems []string
				checkAgainstSchema(payload, s.PayloadKeys, pt, &problems)
				sort.Strings(problems)
				for _, p := range problems {
					t.Errorf("%s", p)
				}
			}
		})
	}
}

// checkAgainstSchema walks the emitted dictionary and the schema together.
func checkAgainstSchema(got map[string]any, allowed []schemaKey, path string, problems *[]string) {
	byName := map[string]schemaKey{}
	for _, k := range allowed {
		byName[k.Key] = k
	}
	names := make([]string, 0, len(got))
	for k := range got {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		if commonPayloadKeys[name] {
			continue
		}
		sk, ok := byName[name]
		if !ok {
			*problems = append(*problems, fmt.Sprintf(
				"%s.%s is not in Apple's schema at this level (wrong key, or the right key in the wrong place)",
				path, name))
			continue
		}
		// Recurse into dictionaries, which is where placement errors live.
		if sub, ok := got[name].(map[string]any); ok && len(sk.Subkeys) > 0 {
			checkAgainstSchema(sub, sk.Subkeys, path+"."+name, problems)
		}
		// And into arrays of dictionaries, which is what OnDemandRules is.
		// Apple wraps an array's element type in a single subkey of its own --
		// OnDemandRules.OnDemandRulesElement -- so the element's real keys are
		// one level further down than they look.
		if arr, ok := got[name].([]any); ok {
			elem := sk.Subkeys
			if len(elem) == 1 && elem[0].Type == "<dictionary>" {
				elem = elem[0].Subkeys
			}
			if len(elem) == 0 {
				continue
			}
			for _, item := range arr {
				if d, ok := item.(map[string]any); ok {
					checkAgainstSchema(d, elem, path+"."+name+"[]", problems)
				}
			}
		}
	}
}
