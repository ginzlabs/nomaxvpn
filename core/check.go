package nomaxcore

import (
	"github.com/ginzlabs/nomaxvpn/internal/apiclient"
	conncheck "github.com/ginzlabs/nomaxvpn/internal/check"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

// APIBase is the device API's path on the server, such as "/api/v1", as this
// build was made with.
func APIBase() string { return profile.API() }

// Call sends one request to the device API at host, through the server's
// address, a relay or Cloudflare, whichever gets through. relays is
// comma-separated ("" is the ones built in); route "relay" tries them first.
// The answer is {"status": 200, "body": "…"}; an error means nothing reached
// the server.
func Call(host, method, path, token, body, route, relays string) (string, error) {
	return apiclient.Call(host, method, path, token, body, route, relays)
}

// BuiltInRelays are the relays this build was made with, comma-separated,
// for joining before a profile lists them.
func BuiltInRelays() string { return apiclient.Relays }

// CheckStart begins a connection check of host, replacing one in progress; app
// names the app and device for the report. Run it with the tunnel off, or it
// tests the tunnel's path instead of the network's.
func CheckStart(host, app string) { conncheck.Start(host, app) }

// CheckState is the latest check as JSON: {host, started, done, verdict,
// steps: [{id, group, title, state, detail, ms}]}, or {} before the first.
func CheckState() string { return conncheck.State() }

// CheckText is the latest check as plain text for sharing.
func CheckText() string { return conncheck.Text() }

// CheckCancel stops the check in progress.
func CheckCancel() { conncheck.Cancel() }
