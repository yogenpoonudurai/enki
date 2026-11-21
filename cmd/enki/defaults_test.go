package main

import "testing"

func TestDefaultScanOptionsNarrowDependencies(t *testing.T) {
	o := defaultScanOptions()
	if o.deps != "ai" {
		t.Fatalf("default deps = %q, want ai", o.deps)
	}
	if o.osPackages {
		t.Fatal("OS package inventory must be opt-in")
	}
	if o.scope != "full" {
		t.Fatalf("default scope = %q, want full", o.scope)
	}
}
