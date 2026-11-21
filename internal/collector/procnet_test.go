//go:build linux

package collector

import "testing"

func TestDecodeProcAddrIPv4(t *testing.T) {
	addr, port, err := decodeProcAddr("0100007F:0035", false)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1" || port != 53 {
		t.Fatalf("got %s:%d", addr, port)
	}

	addr, port, err = decodeProcAddr("00000000:2CAA", false)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0" || port != 11434 {
		t.Fatalf("got %s:%d", addr, port)
	}
}

func TestDecodeProcAddrIPv6(t *testing.T) {
	addr, port, err := decodeProcAddr("00000000000000000000000001000000:1F90", true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "::1" || port != 8080 {
		t.Fatalf("got %s:%d", addr, port)
	}
}

func TestDecodeProcAddrInvalid(t *testing.T) {
	if _, _, err := decodeProcAddr("nonsense", false); err == nil {
		t.Fatal("expected error")
	}
}
