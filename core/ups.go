package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UPS nadzor (D8): NUT (Network UPS Tools) preko OpenWrt paketa.
// Saguaro instalira pakete na klik, upiše sag_ konfiguraciju (driver, upsd na
// 127.0.0.1, upsmon kao master) i svakih 15 s čita stanje kroz `upsc`.
// Uredno gašenje pri praznoj bateriji radi sam upsmon — to mu je posao i radi
// ga i kad Saguaro servis ne bi radio. Saguaro povrh toga javlja događaje
// (nestanak struje, povratak, slaba baterija, gubitak veze s UPS-om) kroz
// postojeći sustav upozorenja.

const (
	nutServerConfig  = "/etc/config/nut_server"
	nutMonitorConfig = "/etc/config/nut_monitor"
	upsName          = "sag_ups" // ime NUT jedinice = ime uci sekcije
	upsPollEvery     = 15 * time.Second
)

// upsDrivers su ponuđeni driveri: usbhid-ups pokriva gotovo sve novije USB
// UPS-e (APC, Eaton, CyberPower...), nutdrv_qx starije i jeftinije (Mustek,
// Trust i slične s Megatec/Q1 protokolom).
var upsDrivers = map[string]string{
	"usbhid-ups": "nut-driver-usbhid-ups",
	"nutdrv_qx":  "nut-driver-nutdrv_qx",
}

var upsPackages = []string{
	"nut-server", "nut-upsmon", "nut-upsc",
	"nut-driver-usbhid-ups", "nut-driver-nutdrv_qx",
}

/* ---------- stanje iz upsc ---------- */

type upsState struct {
	mu      sync.RWMutex
	vars    map[string]string // zadnje očitanje upsc-a
	readAt  time.Time
	lastErr string
}

var upsCur upsState

// upscRead pročita sve varijable UPS-a s danog cilja (ups@host). Greška znači
// da driver/mrežni NUT ne radi ili UPS nije spojen — i to je informacija.
// Mrežni cilj zna kasniti, pa je timeout nešto veći.
func upscRead(ctx context.Context, target string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "upsc", target).Output()
	if err != nil {
		return nil, err
	}
	vars := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		vars[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return vars, nil
}

func upsInstalled() bool {
	_, err := exec.LookPath("upsc")
	if err != nil {
		return false
	}
	_, err = exec.LookPath("upsd")
	return err == nil
}

// upsConn vraća tip veze: "usb" (lokalni UPS na USB-u) ili "remote" (UPS na
// drugom NUT poslužitelju kojeg samo pratimo). Zadano usb.
// applyUPSFirewall otvara ili zatvara port 3493/tcp (NUT) iz LAN zone prema
// uređaju, ovisno o tome dijeli li se UPS na mreži. Vlastito sag_ pravilo, kao
// kod WireGuarda — tuđa pravila se ne diraju (D-011).
func (s *server) applyUPSFirewall(ctx context.Context, open bool) error {
	var b strings.Builder
	// uvijek prvo makni staro pravilo, pa dodaj ako treba (idempotentno)
	b.WriteString("delete firewall.sag_ups_rule\n")
	if open {
		b.WriteString("set firewall.sag_ups_rule=rule\n")
		b.WriteString("set firewall.sag_ups_rule.name=Saguaro-NUT\n")
		b.WriteString("set firewall.sag_ups_rule.src=lan\n")
		b.WriteString("set firewall.sag_ups_rule.proto=tcp\n")
		b.WriteString("set firewall.sag_ups_rule.dest_port=3493\n")
		b.WriteString("set firewall.sag_ups_rule.target=ACCEPT\n")
	}
	b.WriteString("commit firewall\n")
	if err := uciBatch(ctx, b.String()); err != nil {
		return err
	}
	return serviceReload(ctx, "firewall", "reload")
}

func (s *server) upsConn() string {
	c := s.getSetting("ups_conn", "usb")
	if c != "remote" {
		return "usb"
	}
	return "remote"
}

// upsEnabled kaže je li Saguaro uključio svoj UPS nadzor (bilo koji tip).
func (s *server) upsEnabled() bool {
	return s.getSetting("ups_enabled", "0") == "1"
}

// upsTarget vraća upsc cilj prema tipu veze: lokalno sag_ups@127.0.0.1, ili
// <ime>@<host> udaljenog NUT poslužitelja. Za remote bez upisanih polja vraća
// prazno — pozivatelj tada preskače očitanje umjesto da tiho čita lokalni UPS.
func (s *server) upsTarget(ctx context.Context) string {
	if s.upsConn() == "remote" {
		name := uciGet(ctx, "nut_monitor.sag_remote.upsname")
		host := uciGet(ctx, "nut_monitor.sag_remote.hostname")
		if name != "" && host != "" {
			return name + "@" + host
		}
		return ""
	}
	return upsName + "@127.0.0.1"
}

/* ---------- petlja: očitanje i događaji ---------- */

// upsLoop čita stanje UPS-a i javlja promjene. Prijelazi koje pratimo:
// OL→OB (nestanak struje), OB→OL (povratak), pojava LB (slaba baterija) i
// gubitak/povratak komunikacije s driverom.
func (s *server) upsLoop() {
	for {
		time.Sleep(upsPollEvery)
		ctx := context.Background()
		if !upsInstalled() || !s.upsEnabled() {
			continue
		}
		target := s.upsTarget(ctx)
		if target == "" {
			continue // remote bez upisanih polja — nema što čitati
		}
		vars, err := upscRead(ctx, target)

		upsCur.mu.Lock()
		if err != nil {
			upsCur.lastErr = err.Error()
			upsCur.vars = nil
		} else {
			upsCur.lastErr = ""
			upsCur.vars = vars
			upsCur.readAt = time.Now()
		}
		upsCur.mu.Unlock()

		// komunikacija: "ok" ili "lost" — javlja se samo promjena
		comm := "ok"
		if err != nil {
			comm = "lost"
		}
		if changed, prev := s.alertValue("ups:comm", comm); changed {
			if comm == "lost" {
				lostMsg := "Veza s UPS-om je izgubljena — driver se ne javlja. " +
					"Provjeri USB kabel i je li UPS upaljen."
				if s.upsConn() == "remote" {
					lostMsg = "Veza s udaljenim NUT poslužiteljem je izgubljena — " +
						"provjeri je li dostupan i radi li na njemu NUT."
				}
				s.alert("ups", "warning", lostMsg)
			} else if prev == "lost" {
				s.alert("ups", "info", "Veza s UPS-om je ponovno uspostavljena.")
			}
		}
		if err != nil {
			continue
		}

		// ups.status: niz oznaka odvojenih razmakom, npr. "OB LB CHRG"
		status := vars["ups.status"]
		onBatt := hasUPSFlag(status, "OB")
		lowBatt := hasUPSFlag(status, "LB")

		power := "mreža"
		if onBatt {
			power = "baterija"
		}
		if changed, prev := s.alertValue("ups:power", power); changed {
			if power == "baterija" {
				s.alert("ups", "warning", "Nestala je struja — uređaj radi na bateriji UPS-a."+
					upsBattNote(vars))
			} else if prev == "baterija" {
				s.alert("ups", "info", "Struja se vratila — UPS je opet na mreži."+
					upsBattNote(vars))
			}
		}

		lb := "ne"
		if lowBatt {
			lb = "da"
		}
		if changed, _ := s.alertValue("ups:lowbatt", lb); changed && lowBatt {
			s.alert("ups", "error",
				"Baterija UPS-a je pri kraju — slijedi uredno gašenje uređaja "+
					"(upsmon). "+upsBattNote(vars))
		}
	}
}

func hasUPSFlag(status, flag string) bool {
	for _, f := range strings.Fields(status) {
		if f == flag {
			return true
		}
	}
	return false
}

// upsBattNote sažme stanje baterije za tekst poruke, ako ga UPS daje.
func upsBattNote(vars map[string]string) string {
	var parts []string
	if v := vars["battery.charge"]; v != "" {
		parts = append(parts, "baterija "+v+" %")
	}
	if v := vars["battery.runtime"]; v != "" {
		if sec, err := strconv.Atoi(v); err == nil {
			parts = append(parts, "autonomija ~"+strconv.Itoa(sec/60)+" min")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

/* ---------- API ---------- */

func (s *server) handleUPSGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	installed := upsInstalled()
	out := map[string]any{
		"installed": installed,
		"enabled":   false,
		"drivers":   []string{"usbhid-ups", "nutdrv_qx"},
	}
	if !installed {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["enabled"] = s.upsEnabled()
	out["conn"] = s.upsConn()
	out["driver"] = uciGet(ctx, "nut_server."+upsName+".driver")
	if v := uciGet(ctx, "nut_server.override_battery_charge_low.value"); v != "" {
		out["low_pct"] = v
	}
	// dijeljenje na mreži (NUT poslužitelj): podaci za druga računala. Lozinka
	// se OVDJE prikazuje jer je klijenti trebaju unijeti (kao SSH ključ backupa),
	// ali NE ulozi „samo pregled" — ona vidi da se dijeli, bez tajne.
	share := s.getSetting("ups_share", "0") == "1"
	out["share"] = share
	if share {
		out["share_host"] = uciGet(ctx, "network.lan.ipaddr")
		out["share_user"] = uciGet(ctx, "nut_server.sag_client.username")
		out["share_ups"] = upsName
		if _, _, role := s.sessionUserRole(bearerToken(r)); role != roleViewer {
			out["share_pass"] = uciGet(ctx, "nut_server.sag_client.password")
		}
	}
	// udaljeni NUT: host, ime UPS-a i korisnik (lozinka se NE vraća)
	out["remote_host"] = uciGet(ctx, "nut_monitor.sag_remote.hostname")
	out["remote_ups"] = uciGet(ctx, "nut_monitor.sag_remote.upsname")
	out["remote_user"] = uciGet(ctx, "nut_monitor.sag_remote.username")

	// svježe očitanje na zahtjev — GUI ne čeka petlju. Greška se mora upisati,
	// inače bi API vraćao staro (predprekidno) stanje kao trenutno.
	if target := s.upsTarget(ctx); out["enabled"] == true && target != "" {
		vars, err := upscRead(ctx, target)
		upsCur.mu.Lock()
		if err == nil {
			upsCur.vars, upsCur.readAt, upsCur.lastErr = vars, time.Now(), ""
		} else {
			upsCur.vars, upsCur.lastErr = nil, err.Error()
		}
		upsCur.mu.Unlock()
	}
	upsCur.mu.RLock()
	if upsCur.vars != nil {
		v := upsCur.vars
		st := map[string]any{
			"status":  v["ups.status"],
			"read_at": upsCur.readAt.Unix(),
			"model":   strings.TrimSpace(v["ups.mfr"] + " " + v["ups.model"]),
		}
		for apiKey, nutKey := range map[string]string{
			"charge_pct": "battery.charge", "runtime_s": "battery.runtime",
			"load_pct": "ups.load", "input_v": "input.voltage",
			"battery_v": "battery.voltage",
		} {
			if raw := v[nutKey]; raw != "" {
				if f, err := strconv.ParseFloat(raw, 64); err == nil {
					st[apiKey] = f
				}
			}
		}
		out["ups"] = st
	} else if upsCur.lastErr != "" {
		if s.upsConn() == "remote" {
			out["error"] = "Udaljeni NUT se ne javlja (provjeri host, ime UPS-a i prijavu)"
		} else {
			out["error"] = "UPS se ne javlja (driver ne radi ili UPS nije spojen)"
		}
	}
	upsCur.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleUPSInstall(w http.ResponseWriter, r *http.Request) {
	if !upsInstalled() {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		_ = exec.CommandContext(ctx, "apk", "update").Run()
		args := append([]string{"add"}, upsPackages...)
		if out, err := exec.CommandContext(ctx, "apk", args...).CombinedOutput(); err != nil {
			writeErr(w, http.StatusInternalServerError,
				"instalacija: "+err.Error()+": "+string(out))
			return
		}
	}
	addEvent(s, "info", "Instaliran NUT — nadzor neprekidnog napajanja (UPS)")
	writeJSON(w, http.StatusOK, map[string]any{"installed": upsInstalled()})
}

func (s *server) handleUPSSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Enabled *bool  `json:"enabled"`
		Conn    string `json:"conn"` // usb | remote
		Driver  string `json:"driver"`
		LowPct  int    `json:"low_pct"` // 0 = prepusti UPS-u tvornički prag
		Share   bool   `json:"share"`   // USB: dijeli UPS na mreži (NUT poslužitelj)
		// udaljeni NUT
		RemoteHost string `json:"remote_host"`
		RemoteUps  string `json:"remote_ups"`
		RemoteUser string `json:"remote_user"`
		RemotePass string `json:"remote_pass"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if in.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "nedostaje polje enabled")
		return
	}
	if !upsInstalled() {
		writeErr(w, http.StatusBadRequest, "prvo instaliraj NUT pakete")
		return
	}
	if in.Conn != "remote" {
		in.Conn = "usb"
	}

	for _, p := range []string{nutServerConfig, nutMonitorConfig} {
		if _, err := s.backupConfig(p); err != nil {
			writeErr(w, http.StatusInternalServerError, "backup: "+err.Error())
			return
		}
	}

	var b strings.Builder
	// stara konfiguracija oba tipa se počisti pa se upiše odabrani (nema
	// zaostalog sag_master kad se prebaci na remote i obrnuto)
	b.WriteString("delete nut_monitor.sag_master\n")
	b.WriteString("delete nut_monitor.sag_remote\n")
	b.WriteString("set nut_monitor.upsmon=upsmon\n")
	b.WriteString("set nut_monitor.upsmon.minsupplies=1\n")

	if in.Conn == "usb" {
		if in.Driver == "" {
			in.Driver = "usbhid-ups"
		}
		if _, ok := upsDrivers[in.Driver]; !ok {
			writeErr(w, http.StatusBadRequest, "nepoznat driver: "+in.Driver)
			return
		}
		if in.LowPct < 0 || in.LowPct > 90 {
			writeErr(w, http.StatusBadRequest, "prag baterije: 0–90 %")
			return
		}
		// lozinka veže upsmon na lokalni upsd (samo 127.0.0.1); generira se jednom
		pw := uciGet(ctx, "nut_server.sag_user.password")
		if pw == "" {
			raw := make([]byte, 12)
			if _, err := rand.Read(raw); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			pw = hex.EncodeToString(raw)
		}
		en := "0"
		if *in.Enabled {
			en = "1"
		}
		// nut_server: lokalni driver + korisnik + slušanje samo lokalno
		b.WriteString("set nut_server." + upsName + "=driver\n")
		b.WriteString("set nut_server." + upsName + ".driver=" + in.Driver + "\n")
		b.WriteString("set nut_server." + upsName + ".port=auto\n")
		b.WriteString("set nut_server." + upsName + ".sag_enabled=" + en + "\n")
		b.WriteString("delete nut_server." + upsName + ".override\n")
		b.WriteString("delete nut_server.override_battery_charge_low\n")
		if in.LowPct > 0 {
			b.WriteString("add_list nut_server." + upsName + ".override=battery_charge_low\n")
			b.WriteString("set nut_server.override_battery_charge_low=override\n")
			b.WriteString("set nut_server.override_battery_charge_low.value=" +
				strconv.Itoa(in.LowPct) + "\n")
		}
		b.WriteString("set nut_server.sag_user=user\n")
		b.WriteString("set nut_server.sag_user.username=saguaro\n")
		b.WriteString("set nut_server.sag_user.password=" + pw + "\n")
		b.WriteString("set nut_server.sag_user.upsmon=master\n")
		// lokalno slušanje uvijek (za vlastiti upsmon)
		b.WriteString("set nut_server.sag_listen=listen_address\n")
		b.WriteString("set nut_server.sag_listen.address=127.0.0.1\n")
		b.WriteString("set nut_server.sag_listen.port=3493\n")
		// dijeljenje na mreži: dodatno slušanje na LAN adresi + klijentski
		// korisnik (secondary) da druga računala na istom UPS-u dobiju gašenje.
		// Klijent NE smije naredbe — samo prati i gasi sebe (upsmon=slave).
		// lan.ipaddr može biti lista (više adresa) — uzmi prvu; prazno = nema
		// statičke LAN adrese pa se dijeljenje ne može uključiti
		lanIP := strings.Fields(uciGet(ctx, "network.lan.ipaddr"))
		shareOK := in.Share && *in.Enabled && len(lanIP) > 0
		if shareOK {
			// klijentska lozinka se čuva u postavci pa ostaje ista kroz
			// isključi/uključi — inače bi sva računala izgubila pristup
			cpw := s.getSetting("ups_client_pass", "")
			if cpw == "" {
				raw := make([]byte, 12)
				if _, err := rand.Read(raw); err != nil {
					writeErr(w, http.StatusInternalServerError, err.Error())
					return
				}
				cpw = hex.EncodeToString(raw)
				s.setSetting("ups_client_pass", cpw)
			}
			b.WriteString("set nut_server.sag_listen_net=listen_address\n")
			b.WriteString("set nut_server.sag_listen_net.address=" + uciQuote(lanIP[0]) + "\n")
			b.WriteString("set nut_server.sag_listen_net.port=3493\n")
			b.WriteString("set nut_server.sag_client=user\n")
			b.WriteString("set nut_server.sag_client.username=nutklijent\n")
			b.WriteString("set nut_server.sag_client.password=" + uciQuote(cpw) + "\n")
			b.WriteString("set nut_server.sag_client.upsmon=slave\n")
		} else {
			b.WriteString("delete nut_server.sag_listen_net\n")
			b.WriteString("delete nut_server.sag_client\n")
		}
		b.WriteString("commit nut_server\n")
		// upsmon kao MASTER lokalnog UPS-a — on gasi uređaj kad je baterija prazna
		b.WriteString("set nut_monitor.sag_master=master\n")
		b.WriteString("set nut_monitor.sag_master.upsname=" + upsName + "\n")
		b.WriteString("set nut_monitor.sag_master.hostname=127.0.0.1\n")
		b.WriteString("set nut_monitor.sag_master.powervalue=1\n")
		b.WriteString("set nut_monitor.sag_master.username=saguaro\n")
		b.WriteString("set nut_monitor.sag_master.password=" + pw + "\n")
		b.WriteString("commit nut_monitor\n")
	} else {
		// udaljeni NUT: samo pratimo tuđi UPS i gasimo SEBE (secondary,
		// powervalue=0) — nikad ne izdajemo naredbu gašenja tuđem UPS-u
		host := strings.TrimSpace(in.RemoteHost)
		name := strings.TrimSpace(in.RemoteUps)
		user := strings.TrimSpace(in.RemoteUser)
		if *in.Enabled && (host == "" || name == "") {
			writeErr(w, http.StatusBadRequest,
				"za udaljeni NUT upiši adresu poslužitelja i ime UPS-a (ups@host)")
			return
		}
		// lozinka: prazno = zadrži postojeću
		pass := in.RemotePass
		if pass == "" {
			pass = uciGet(ctx, "nut_monitor.sag_remote.password")
		}
		// kontrolni znakovi (npr. novi red) bi kroz `uci batch` ubacili druge
		// naredbe kao root — odbijaju se, a vrijednosti se pišu kroz uciQuote
		if hasCtrl(host) || hasCtrl(name) || hasCtrl(user) || hasCtrl(pass) {
			writeErr(w, http.StatusBadRequest,
				"polja ne smiju sadržavati prijelom retka ni tabulator")
			return
		}
		// lokalni upsd se gasi — kod remote tipa nije potreban; miču se i
		// zaostali dijelovi dijeljenja (slušatelj na LAN-u i klijentski račun)
		b.WriteString("set nut_server." + upsName + ".sag_enabled=0\n")
		b.WriteString("delete nut_server.sag_listen_net\n")
		b.WriteString("delete nut_server.sag_client\n")
		b.WriteString("commit nut_server\n")
		// type=slave (secondary): pratimo tuđi UPS i gasimo SEBE, ali NIKAD ne
		// izdajemo naredbu gašenja UPS-u — to radi njegov primary. powervalue=1
		// jer ovaj uređaj napaja taj UPS (zato se i gasi kad UPS ostane bez
		// baterije); s powervalue=0 upsmon bi javio "insufficient power" i stao.
		b.WriteString("set nut_monitor.sag_remote=slave\n")
		b.WriteString("set nut_monitor.sag_remote.upsname=" + uciQuote(name) + "\n")
		b.WriteString("set nut_monitor.sag_remote.hostname=" + uciQuote(host) + "\n")
		b.WriteString("set nut_monitor.sag_remote.powervalue=1\n")
		if user != "" {
			b.WriteString("set nut_monitor.sag_remote.username=" + uciQuote(user) + "\n")
		}
		if pass != "" {
			b.WriteString("set nut_monitor.sag_remote.password=" + uciQuote(pass) + "\n")
		}
		b.WriteString("commit nut_monitor\n")
	}
	if err := uciBatch(ctx, b.String()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Saguaro-razina: pamti tip veze, je li uključeno i dijeli li se na mreži
	// (izvor istine za upsEnabled/upsConn/upsTarget/upsShare)
	s.setSetting("ups_conn", in.Conn)
	s.setSetting("ups_enabled", boolSetting(*in.Enabled))
	// dijeljenje je stvarno aktivno samo ako ima LAN adrese na kojoj upsd sluša
	// (isti uvjet kao gore) — inače ni ups_share ni firewall port ne idu na 1
	sharing := in.Conn == "usb" && *in.Enabled && in.Share &&
		len(strings.Fields(uciGet(ctx, "network.lan.ipaddr"))) > 0
	s.setSetting("ups_share", boolSetting(sharing))

	// firewall: port 3493/tcp iz LAN-a prema uređaju samo dok se UPS dijeli
	if err := s.applyUPSFirewall(ctx, sharing); err != nil {
		log.Printf("UPS firewall pravilo: %v", err)
	}

	// USB tip vozi lokalni upsd (nut-server); remote tip ga ne treba
	if in.Conn == "usb" {
		if *in.Enabled {
			_ = serviceReload(ctx, "nut-server", "enable")
			_ = serviceReload(ctx, "nut-server", "restart")
		} else {
			_ = serviceReload(ctx, "nut-server", "stop")
			_ = serviceReload(ctx, "nut-server", "disable")
		}
	} else {
		_ = serviceReload(ctx, "nut-server", "stop")
		_ = serviceReload(ctx, "nut-server", "disable")
	}
	// upsmon (nut-monitor) vozi oba tipa
	if *in.Enabled {
		if err := serviceReload(ctx, "nut-monitor", "restart"); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = serviceReload(ctx, "nut-monitor", "enable")
	} else {
		_ = serviceReload(ctx, "nut-monitor", "stop")
		_ = serviceReload(ctx, "nut-monitor", "disable")
	}

	switch {
	case !*in.Enabled:
		addEvent(s, "info", "UPS nadzor isključen")
	case in.Conn == "remote":
		addEvent(s, "info", "UPS nadzor uključen (udaljeni NUT "+
			strings.TrimSpace(in.RemoteUps)+"@"+strings.TrimSpace(in.RemoteHost)+")")
	default:
		addEvent(s, "info", "UPS nadzor uključen (USB, driver "+in.Driver+")")
	}
	note := "driveru treba koja sekunda da nađe UPS nakon uključivanja"
	if in.Conn == "remote" {
		note = "spajam se na udaljeni NUT — provjeri stanje za koju sekundu"
	}
	if !*in.Enabled {
		note = "UPS nadzor je isključen, NUT servisi su zaustavljeni"
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": *in.Enabled, "note": note})
}
