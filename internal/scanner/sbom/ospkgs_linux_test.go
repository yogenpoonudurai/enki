//go:build linux

package sbom

import "testing"

func TestOSVEcosystemMapping(t *testing.T) {
	cases := []struct {
		id, version string
		want        string
		ok          bool
	}{
		{"debian", "12", "Debian:12", true},
		{"debian", "12.5", "Debian:12", true},
		{"ubuntu", "22.04", "Ubuntu:22.04:LTS", true},
		{"ubuntu", "23.10", "Ubuntu:23.10", true},
		{"alpine", "3.19.1", "Alpine:v3.19", true},
		{"rocky", "9.3", "Rocky Linux:9", true},
		{"almalinux", "9.4", "AlmaLinux:9", true},
		{"rhel", "9.4", "", false},
		{"fedora", "40", "", false},
		{"arch", "", "", false},
	}
	for _, tc := range cases {
		got, ok := osvEcosystem(tc.id, tc.version)
		if ok != tc.ok || got != tc.want {
			t.Errorf("osvEcosystem(%q,%q) = (%q,%v), want (%q,%v)",
				tc.id, tc.version, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseDpkgKeepsSourceAndEpoch(t *testing.T) {
	data := []byte(
		"bash\t5.2.15-2+b2\tbash\t5.2.15-2+b2\n" +
			"libssl3\t3.0.11-1~deb12u2\topenssl\t1:3.0.11-1~deb12u2\n" +
			"libssl3\t3.0.11-1~deb12u2\topenssl\t1:3.0.11-1~deb12u2\n",
	)
	ps := parseDpkgOutput(data)
	if len(ps) != 2 {
		t.Fatalf("packages = %+v", ps)
	}
	got := pkgMap(ps)
	if got["openssl"] != "1:3.0.11-1~deb12u2" {
		t.Fatalf("source version/epoch not preserved: %+v", got)
	}
	if _, ok := got["libssl3"]; ok {
		t.Fatal("binary package name should be replaced by the source name")
	}
}

func TestParseDpkgFallbackToBinary(t *testing.T) {
	ps := parseDpkgOutput([]byte("localpkg\t1.0-1\t\t\n"))
	if len(ps) != 1 || ps[0].Name != "localpkg" || ps[0].Version != "1.0-1" {
		t.Fatalf("packages = %+v", ps)
	}
}

func TestParseApkInstalledUsesOrigin(t *testing.T) {
	data := []byte(`P:libssl3
V:3.0.12-r5
o:openssl

P:busybox
V:1.36.1-r7

`)
	ps := parseApkInstalled(data)
	got := pkgMap(ps)
	if got["openssl"] != "3.0.12-r5" {
		t.Fatalf("origin package missing: %+v", got)
	}
	if got["busybox"] != "1.36.1-r7" {
		t.Fatalf("fallback to binary name failed: %+v", got)
	}
}

func TestParseRpmOutput(t *testing.T) {
	data := []byte("openssl 1:3.0.7-27.el9\nbash 5.1.8-6.el9\ngpg-pubkey 1234\n")
	ps := parseRpmOutput(data)
	got := pkgMap(ps)
	if got["openssl"] != "1:3.0.7-27.el9" || got["bash"] != "5.1.8-6.el9" {
		t.Fatalf("packages = %+v", got)
	}
	if _, ok := got["gpg-pubkey"]; ok {
		t.Fatal("gpg-pubkey pseudo-package should be skipped")
	}
}

func TestParseOSRelease(t *testing.T) {
	rel := parseOSRelease([]byte("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"))
	if rel["ID"] != "debian" || rel["VERSION_ID"] != "12" {
		t.Fatalf("release = %+v", rel)
	}
}
