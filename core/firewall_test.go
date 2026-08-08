package main

import "testing"

func TestLogField(t *testing.T) {
	line := `Sat Aug 8 21:39:16 2026 kernel: FW IN=br-lan OUT=eth1 SRC=192.168.50.77 DST=8.8.8.8 LEN=60 PROTO=TCP SPT=51000 DPT=12399`
	cases := map[string]string{
		"IN=": "br-lan", "OUT=": "eth1", "SRC=": "192.168.50.77",
		"DST=": "8.8.8.8", "PROTO=": "TCP", "DPT=": "12399",
	}
	for key, want := range cases {
		if got := logField(line, key); got != want {
			t.Errorf("logField(%q)=%q, očekivano %q", key, got, want)
		}
	}
	if got := logField(line, "NEMA="); got != "" {
		t.Errorf("nepostojeće polje treba dati prazno, dobiveno %q", got)
	}
}
