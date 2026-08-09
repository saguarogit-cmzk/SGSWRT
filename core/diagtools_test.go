package main

import (
	"net"
	"testing"
)

// TestConntrackDeletedParse — "0 flow entries" ne smije značiti uspjeh, "1" da.
func TestConntrackDeletedParse(t *testing.T) {
	cases := map[string]bool{
		"conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.": false,
		"conntrack v1.4.8 (conntrack-tools): 1 flow entries have been deleted.": true,
		"conntrack v1.4.8 (conntrack-tools): 3 flow entries have been deleted.": true,
		"nešto sasvim drugo": false,
	}
	for out, wantKilled := range cases {
		killed := false
		if m := reConntrackDeleted.FindStringSubmatch(out); m != nil && m[1] != "0" {
			killed = true
		}
		if killed != wantKilled {
			t.Errorf("izlaz %q → killed=%v, očekivano %v", out, killed, wantKilled)
		}
	}
}

// TestWolLengthGuard — magic packet vrijedi samo za 6-bajtnu MAC adresu.
func TestWolLengthGuard(t *testing.T) {
	if _, err := wolSend(net.HardwareAddr{0x01, 0x02, 0x03}); err == nil {
		t.Error("3-bajtna MAC adresa mora biti odbijena")
	}
	// 8-bajtna (EUI-64) također nije valjana za WoL
	if _, err := wolSend(net.HardwareAddr{1, 2, 3, 4, 5, 6, 7, 8}); err == nil {
		t.Error("8-bajtna MAC adresa mora biti odbijena")
	}
}
