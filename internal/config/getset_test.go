package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

func TestListKeysExcludesPathAndPolicy(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	kvs := cfg.ListKeys()
	if len(kvs) == 0 {
		t.Fatal("ListKeys returned nothing")
	}
	for _, kv := range kvs {
		if isPolicyKey(kv.Key) {
			t.Errorf("policy key leaked into ListKeys: %q", kv.Key)
		}
		// The five path vars must never appear as config keys (§7.3).
		for _, banned := range []string{"config", "keystore", "state-dir", "cache-dir", "config-dir"} {
			if kv.Key == banned {
				t.Errorf("path var %q leaked into ListKeys", kv.Key)
			}
		}
	}
	// defaults.network must be present and report the default source.
	found := false
	for _, kv := range kvs {
		if kv.Key == "defaults.network" {
			found = true
			if kv.Value != "mainnet" {
				t.Errorf("defaults.network value = %q, want mainnet", kv.Value)
			}
			if kv.Source != "default" {
				t.Errorf("defaults.network source = %q, want default", kv.Source)
			}
		}
	}
	if !found {
		t.Error("defaults.network missing from ListKeys")
	}
}

func TestListKeysSourceAttribution(t *testing.T) {
	dir := writeConfig(t, "[defaults]\nnetwork = \"sepolia\"\n")
	withEnv(t, map[string]string{
		"HOME":            t.TempDir(),
		"DAXIE_CONFIG":    dir,
		"DAXIE_GAS_SPEED": "fast",
	})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	src := map[string]string{}
	for _, kv := range cfg.ListKeys() {
		src[kv.Key] = kv.Source
	}
	if src["defaults.network"] != "file" {
		t.Errorf("defaults.network source = %q, want file", src["defaults.network"])
	}
	if src["gas.speed"] != "env" {
		t.Errorf("gas.speed source = %q, want env", src["gas.speed"])
	}
	if src["tx.wait-timeout"] != "default" {
		t.Errorf("tx.wait-timeout source = %q, want default", src["tx.wait-timeout"])
	}
}

func TestListKeysFlagSource(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	cfg, _, err := Load(FlagValues{Network: "base"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range cfg.ListKeys() {
		if kv.Key == "defaults.network" {
			if kv.Source != "flag" || kv.Value != "base" {
				t.Errorf("flag override: source=%q value=%q, want flag/base", kv.Source, kv.Value)
			}
		}
	}
}

func TestGetKey(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := cfg.GetKey("defaults.network"); err != nil || v != "mainnet" {
		t.Errorf("GetKey(defaults.network) = %q, %v", v, err)
	}
	if v, err := cfg.GetKey("gas.limit-multiplier"); err != nil || v != "1.2" {
		t.Errorf("GetKey(gas.limit-multiplier) = %q, %v", v, err)
	}
	if v, err := cfg.GetKey("ens.enabled"); err != nil || v != "true" {
		t.Errorf("GetKey(ens.enabled) = %q, %v", v, err)
	}
}

func TestGetKeyUnknown(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.GetKey("no.such.key")
	assertCode(t, err, domain.CodeRefNotFound)
}

func TestGetKeyPolicyRejected(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.GetKey("policy.max-tx")
	if err == nil {
		t.Fatal("expected error for policy key")
	}
	var de *domain.Error
	if !errors.As(err, &de) || !strings.HasPrefix(de.Code, domain.CodeUsage) {
		t.Errorf("policy GetKey code = %v, want usage.*", err)
	}
}

func TestFtoa(t *testing.T) {
	cases := map[float64]string{
		1.2:  "1.2",
		2.0:  "2",
		12.5: "12.5",
		0.10: "0.1",
	}
	for in, want := range cases {
		if got := ftoa(in); got != want {
			t.Errorf("ftoa(%v) = %q, want %q", in, got, want)
		}
	}
}
