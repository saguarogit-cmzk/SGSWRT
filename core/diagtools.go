package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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

// handleDiagPortCheck provjerava je li TCP port na hostu otvoren. Radi izravno
// iz Go-a (dial s vremenskim ograničenjem), bez vanjskog alata — pa nije
// potrebna instalacija ničega.
func (s *server) handleDiagPortCheck(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !validHostArg(in.Host) {
		writeErr(w, http.StatusBadRequest, "neispravna adresa ili ime hosta")
		return
	}
	if in.Port < 1 || in.Port > 65535 {
		writeErr(w, http.StatusBadRequest, "port mora biti 1–65535")
		return
	}
	addr := net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	ms := time.Since(start).Milliseconds()
	res := map[string]any{"host": in.Host, "port": in.Port, "ms": ms}
	if err == nil {
		conn.Close()
		res["open"] = true
		res["detail"] = "port je otvoren (veza uspostavljena)"
	} else {
		res["open"] = false
		if strings.Contains(err.Error(), "refused") {
			res["detail"] = "port je zatvoren (veza odbijena)"
		} else if strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "i/o timeout") {
			res["detail"] = "nema odgovora (filtrirano ili host nedostupan)"
		} else {
			res["detail"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func conntrackInstalled() bool {
	_, err := exec.LookPath("conntrack")
	return err == nil
}

// handleConnKillInstall instalira conntrack alat (za prekid pojedine veze),
// jednim klikom kao i ostali dodatni alati.
func (s *server) handleConnKillInstall(w http.ResponseWriter, r *http.Request) {
	if !conntrackInstalled() {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "apk", "update").Run()
		if out, err := exec.CommandContext(ctx, "apk", "add", "conntrack").CombinedOutput(); err != nil {
			writeErr(w, http.StatusInternalServerError, "instalacija: "+err.Error()+": "+string(out))
			return
		}
	}
	addEvent(s, "info", "Instaliran alat za prekid veza (conntrack)")
	writeJSON(w, http.StatusOK, map[string]any{"installed": conntrackInstalled()})
}

// handleConnKill prekida jednu vezu iz conntrack tablice. Veza se opisuje
// izvorom, odredištem, protokolom i portovima — dovoljno da conntrack pogodi
// točno taj zapis, a ne cijeli promet prema nekom hostu.
func (s *server) handleConnKill(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Proto string `json:"proto"`
		Src   string `json:"src"`
		Dst   string `json:"dst"`
		SPort int    `json:"sport"`
		DPort int    `json:"dport"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !conntrackInstalled() {
		writeErr(w, http.StatusBadRequest, "alat conntrack nije instaliran")
		return
	}
	if net.ParseIP(in.Src) == nil || net.ParseIP(in.Dst) == nil {
		writeErr(w, http.StatusBadRequest, "neispravna izvorišna ili odredišna adresa")
		return
	}
	proto := strings.ToLower(in.Proto)
	if proto != "tcp" && proto != "udp" && proto != "icmp" {
		writeErr(w, http.StatusBadRequest, "protokol mora biti tcp, udp ili icmp")
		return
	}
	args := []string{"-D", "-s", in.Src, "-d", in.Dst, "-p", proto}
	if proto != "icmp" {
		if in.SPort < 1 || in.SPort > 65535 || in.DPort < 1 || in.DPort > 65535 {
			writeErr(w, http.StatusBadRequest, "neispravan port")
			return
		}
		args = append(args, "--sport", strconv.Itoa(in.SPort), "--dport", strconv.Itoa(in.DPort))
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "conntrack", args...).CombinedOutput()
	// conntrack vraća izlazni kod 0 i "1 flow entries have been deleted"; ako
	// veza više ne postoji, vrati 1 — to nije greška za korisnika (već je gotova)
	deleted := strings.Contains(string(out), "deleted")
	if err != nil && !deleted {
		writeJSON(w, http.StatusOK, map[string]any{"killed": false,
			"detail": "veza više ne postoji ili je već zatvorena"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"killed": true})
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
