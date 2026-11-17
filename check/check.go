// Package nomaxcheck is the connection check for the iOS and macOS apps, bound
// with gomobile on its own: the apps don't carry the tunnel engine, which lives
// in their Network Extensions. Android gets the same calls from nomaxcore.
package nomaxcheck

import (
	"github.com/ginzlabs/nomaxvpn/internal/apiclient"
	"github.com/ginzlabs/nomaxvpn/internal/check"
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

// Start begins a connection check of host, replacing one in progress; app
// names the app and device for the report.
func Start(host, app string) { check.Start(host, app) }

// State is the latest check as JSON: {host, started, done, verdict,
// steps: [{id, group, title, state, detail, ms}]}, or {} before the first.
func State() string { return check.State() }

// Text is the latest check as plain text for sharing.
func Text() string { return check.Text() }

// Cancel stops the check in progress.
func Cancel() { check.Cancel() }
