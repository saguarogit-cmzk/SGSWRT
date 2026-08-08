package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Mrežni alati u Diagnosticsu: ping, traceroute, DNS lookup i tablica susjeda
// (ARP/NDP). Dosad su se radili preko SSH-a. Argumenti se predaju kao zasebni
// parametri (bez ljuske), pa nema opasnosti od ubacivanja naredbi; svejedno se
// meta provjerava da se ne proslijedi npr. zastavica umjesto imena.

var reHostArg = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$`)

// validHostArg prihvaća IPv4/IPv6 adresu ili ime hosta; odbija prazno,
// predugo i sve što počinje crticom (da se ne protumači kao zastavica).
func validHostArg(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 255 || strings.HasPrefix(s, "-") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return reHostArg.MatchString(s)
}

// runTool pokrene alat s vremenskim ograničenjem i vrati kombinirani izlaz.
func runTool(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(c, name, args...).CombinedOutput()
	return string(out), err
}

func (s *server) handleDiagPing(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !validHostArg(in.Host) {
		writeErr(w, http.StatusBadRequest, "neispravna adresa ili ime hosta")
		return
	}
	// -c 4 paketa, -w 8 s ukupno; busybox ping radi i za IPv4 i IPv6 imena
	out, _ := runTool(r.Context(), 12*time.Second, "ping", "-c", "4", "-w", "8", in.Host)
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

func (s *server) handleDiagTraceroute(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !validHostArg(in.Host) {
		writeErr(w, http.StatusBadRequest, "neispravna adresa ili ime hosta")
		return
	}
	// -q 1 (jedan upit po skoku), -w 2 (čekaj 2 s), -m 20 (najviše 20 skokova)
	out, _ := runTool(r.Context(), 30*time.Second, "traceroute", "-q", "1", "-w", "2", "-m", "20", in.Host)
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

func (s *server) handleDiagLookup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !validHostArg(in.Name) {
		writeErr(w, http.StatusBadRequest, "neispravno ime ili adresa")
		return
	}
	out, _ := runTool(r.Context(), 10*time.Second, "nslookup", in.Name)
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

// handleDiagNeighbors vraća tablicu susjeda (ARP za IPv4, NDP za IPv6) iz
// jezgre. Ime uređaja iz DHCP leasea se pridruži gdje postoji.
func (s *server) handleDiagNeighbors(w http.ResponseWriter, r *http.Request) {
	out, err := exec.CommandContext(r.Context(), "ip", "-j", "neigh", "show").Output()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ip neigh: "+err.Error())
		return
	}
	var raw []struct {
		Dst    string   `json:"dst"`
		Dev    string   `json:"dev"`
		Lladdr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		writeErr(w, http.StatusInternalServerError, "neočekivan format: "+err.Error())
		return
	}
	names := s.leaseNames()
	type neigh struct {
		IP    string `json:"ip"`
		MAC   string `json:"mac"`
		Dev   string `json:"dev"`
		State string `json:"state"`
		Name  string `json:"name"`
	}
	list := []neigh{}
	for _, n := range raw {
		if n.Lladdr == "" {
			continue // nepotpuni zapisi (FAILED/INCOMPLETE bez MAC-a) se preskaču
		}
		list = append(list, neigh{
			IP: n.Dst, MAC: n.Lladdr, Dev: n.Dev,
			State: strings.Join(n.State, " "), Name: names[strings.ToLower(n.Lladdr)],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"neighbors": list})
}

// leaseNames mapira MAC → ime uređaja iz aktivnih DHCP leaseova, da se u
// tablici susjeda vidi tko je tko.
func (s *server) leaseNames() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(leaseFile)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		// format: <expiry> <mac> <ip> <hostname> <clientid>
		if len(f) >= 4 && f[3] != "*" {
			m[strings.ToLower(f[1])] = f[3]
		}
	}
	return m
}
