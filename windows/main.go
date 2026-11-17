//go:build windows

// Command NoMax is the Windows app: the page in internal/desktop in a WebView2
// window, over the same Go core as the phones. It runs as administrator,
// which creating the Wintun adapter needs, and wintun.dll sits next to it.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	webview "github.com/jchv/go-webview2"

	nomaxcore "github.com/ginzlabs/nomaxvpn/core"
	"github.com/ginzlabs/nomaxvpn/internal/desktop"
)

// Set at build time (Makefile).
var (
	version = "dev"
	build   = "0"
	host    = "example.com"
)

func main() {
	if !singleInstance() {
		return
	}
	dir := filepath.Join(localAppData(), "NoMax")
	// A NoMax that was killed may have left its adapter routed.
	nomaxcore.Stop()

	// Small screens get a shorter window, so its title bar stays on screen.
	width, height, minHeight := scaled(440), scaled(800), scaled(620)
	area, fits := workArea()
	if fits {
		height = min(height, uint(area.Bottom-area.Top))
		minHeight = min(minHeight, height)
	}
	w := webview.NewWithOptions(webview.WebViewOptions{
		DataPath:  filepath.Join(dir, "WebView2"),
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  "NoMax",
			Width:  width,
			Height: height,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		fail("NoMax needs Microsoft Edge WebView2, which this PC is missing. Install it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and open NoMax again.")
		return
	}
	defer w.Destroy()
	hwnd := uintptr(w.Window())
	darkTitleBar(hwnd)
	if fits {
		moveWindow(hwnd, area.Left+(area.Right-area.Left-int32(width))/2, area.Top+(area.Bottom-area.Top-int32(height))/2)
	}
	w.SetSize(int(scaled(380)), int(minHeight), webview.HintMin)

	pc, _ := os.Hostname()
	app := desktop.New(host, desktop.Store{Dir: dir, Seal: seal, Open: unseal}, engine{}, desktop.Platform{
		Info:       fmt.Sprintf("NoMax %s (%s) · %s, %s", version, build, pc, windowsVersion()),
		Version:    fmt.Sprintf("%s (%s)", version, build),
		DeviceName: pc,
		Copy:       func(s string) error { return copyText(hwnd, s) },
		Reveal:     reveal,
		Minimize:   func() { showWindow.Call(hwnd, swMinimize) },
		Close:      func() { quit(hwnd) },
	})
	// Closing disconnects, so while the VPN is on the page asks first.
	guardClose(hwnd, func() bool {
		if !app.Connected() {
			return false
		}
		showWindow.Call(hwnd, swRestore)
		w.Eval("askClose()")
		return true
	})
	w.Bind("nomax", func(method string, arg json.RawMessage) (any, error) { return app.Call(method, arg) })
	w.SetHtml(desktop.Page)
	w.Run()
	app.Quit()
}

// engine is the core, for the app.
type engine struct{}

func (engine) Start(profileJSON, protocol, route, preferred, wgKey string, tunFd int32, endpointIP string) (string, error) {
	return nomaxcore.Start(profileJSON, protocol, route, preferred, wgKey, tunFd, endpointIP)
}
func (engine) Cancel()                            { nomaxcore.Cancel() }
func (engine) Stop()                              { nomaxcore.Stop() }
func (engine) Events(since int64) string          { return nomaxcore.Events(since) }
func (engine) Stats() string                      { return nomaxcore.Stats() }
func (engine) Endpoint(profileJSON string) string { return nomaxcore.Endpoint(profileJSON) }
func (engine) Preferred() string                  { return nomaxcore.Preferred() }
