package panel

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/profile"
	"github.com/ginzlabs/nomaxvpn/internal/store"
	"rsc.io/qr"
)

// joinGate applies the wrong-PIN limits shared by the app and the join page.
func (p *Panel) joinGate(ip string) (int, string) {
	if n, _ := p.st.Failures(store.EnrollPIN, ip, time.Now().Add(-enrollWindow)); n >= enrollIPLimit {
		return http.StatusTooManyRequests, "Too many wrong PINs. Try again in 15 minutes."
	}
	if p.enrollPaused() {
		return http.StatusTooManyRequests, "Joining is paused for a few minutes. Try again later."
	}
	return 0, ""
}

// joinError turns an Enroll error into a status and message, counting wrong PINs.
func (p *Panel) joinError(ip string, err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrBadPIN):
		p.st.RecordFailure(store.EnrollPIN, ip)
		return http.StatusForbidden, "That PIN doesn't work. A PIN works once, for 10 minutes. Ask for a new one."
	case errors.Is(err, store.ErrDeviceLimit):
		return http.StatusConflict, "You already have the maximum number of devices. Remove one first."
	default:
		p.log.Error("enroll", "err", err)
		return http.StatusInternalServerError, "Server error."
	}
}

// export is one way to connect without the NoMax app.
type export struct {
	Title, Hint string
	Text        string // shown for copying
	File        string // download name
	Data        template.URL
	QR          template.URL
}

func (p *Panel) joinForm(w http.ResponseWriter, r *http.Request) {
	p.render(w, "join", p.joinData(""))
}

func (p *Panel) joinData(msg string) map[string]any {
	files, _ := secret(p.cfg.FilesPath)
	return map[string]any{"Cfg": p.cfg, "Label": p.label(), "Files": files, "Error": msg,
		"APK": exists(p.cfg.APKPath), "APKName": p.apkName(), "EXE": exists(p.cfg.WindowsPath), "EXEName": p.exeName()}
}

func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// download serves an app's installer from path, when it's there.
func download(path, mime, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(path)
		if path == "" || err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeContent(w, r, name, st.ModTime(), f)
	}
}

// join enrols a device for standard apps: the server makes its WireGuard key
// and shows every config once. Nothing private is kept.
func (p *Panel) join(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r)
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		p.render(w, "join", p.joinData(msg))
	}
	if status, msg := p.joinGate(ip); status != 0 {
		fail(status, msg)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name = "Web device"
	}
	key := profile.NewWireGuardKey()
	pub, _ := profile.WireGuardPublic(key)
	dev, _, err := p.st.Enroll(r.PostFormValue("pin"), name, pub)
	if err != nil {
		fail(p.joinError(ip, err))
		return
	}
	p.log.Info("enrolled", "device", dev.ID, "person", dev.PersonName, "via", "web")
	p.kick()
	p.render(w, "configs", map[string]any{"Cfg": p.cfg, "Device": dev, "Exports": p.exports(dev, key)})
}

func (p *Panel) exports(d store.Device, wgKey string) []export {
	pr := p.vpn.Profile(d)
	label := "NoMax " + d.Name
	var out []export
	if conf, err := pr.WGConfig(profile.WireGuard, wgKey); err == nil {
		out = append(out, export{Title: "WireGuard", Hint: "The WireGuard app on Android, Windows, Mac, Linux or iPhone: scan the code or import the file.",
			Text: conf, File: "nomax.conf", Data: dataURL("application/octet-stream", []byte(conf)), QR: qrURL(conf)})
	}
	if conf, err := pr.WGConfig(profile.AmneziaWG, wgKey); err == nil {
		out = append(out, export{Title: "AmneziaWG", Hint: "WireGuard that is harder to block. Use the AmneziaWG app.",
			Text: conf, File: "nomax-amneziawg.conf", Data: dataURL("application/octet-stream", []byte(conf)), QR: qrURL(conf)})
	}
	if i := pr.IKEv2; i != nil {
		e := export{Title: "IKEv2", Hint: "Built into Windows, Android, iPhone and Mac, no app needed. On a Mac, open the profile and approve it in System Settings. Elsewhere, add an IKEv2 connection in the network settings with username and password (EAP-MSCHAPv2) using these details.",
			Text: "Server: " + i.Server + "\nRemote ID: " + i.RemoteID + "\nUsername: " + i.Username + "\nPassword: " + i.Password}
		if mc, err := pr.MobileConfig(d.Name); err == nil {
			e.File, e.Data = "nomax.mobileconfig", dataURL("application/x-apple-aspen-config", mc)
		}
		out = append(out, e)
	}
	link := pr.RealityURI(label)
	out = append(out, export{Title: "Reality (VLESS)", Hint: "For Xray apps such as v2rayNG, Hiddify or Streisand. Looks like normal HTTPS to this site.",
		Text: link, QR: qrURL(link)})
	if link := pr.RealityMuxURI(label); link != "" {
		out = append(out, export{Title: "Reality Mux", Hint: "Reality on its own port without Vision. Turn on mux in the app if it offers it.", Text: link, QR: qrURL(link)})
	}
	if link := pr.HysteriaURI(label); link != "" {
		out = append(out, export{Title: "Hysteria2", Hint: "Fast on bad networks. For Hiddify, v2rayNG or the Hysteria app.", Text: link, QR: qrURL(link)})
	}
	if link := pr.HysteriaObfsURI(label); link != "" {
		out = append(out, export{Title: "Hysteria2 Obfs", Hint: "Hysteria2 scrambled with Salamander, for networks that block plain Hysteria2. For Hiddify, v2rayN or the Hysteria app.", Text: link, QR: qrURL(link)})
	}
	if link := pr.AnyTLSURI(label); link != "" {
		out = append(out, export{Title: "AnyTLS", Hint: "TLS with padding that hides the traffic inside. For Hiddify, sing-box or Clash Meta apps.", Text: link, QR: qrURL(link)})
	}
	if link := pr.MieruURI(); link != "" {
		out = append(out, export{Title: "Mieru", Hint: "Encrypted TCP with nothing to fingerprint. For the mieru client or Clash Meta apps.", Text: link, QR: qrURL(link)})
	}
	return out
}

func dataURL(mime string, b []byte) template.URL {
	return template.URL("data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(b))
}

func qrURL(s string) template.URL {
	c, err := qr.Encode(s, qr.L)
	if err != nil {
		return ""
	}
	c.Scale = 4
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()))
}
