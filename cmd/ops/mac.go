package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/asc"
)

// The .pkg uploaded for the Mac app is signed with a Mac Installer Distribution certificate.
const installerP12 = "_cert/mac-installer.p12"

// ensureMacPlatform adds macOS to the app record, so Mac builds can be uploaded.
func ensureMacPlatform(c *asc.Client, appID, version string) {
	vs, err := c.List("/v1/apps/" + appID + "/appStoreVersions?filter[platform]=MAC_OS&limit=5")
	if err != nil {
		fatalf("app versions: %v", err)
	}
	if len(vs) > 0 {
		return
	}
	if _, err := c.Create("/v1/appStoreVersions", "appStoreVersions", map[string]any{"platform": "MAC_OS", "versionString": version},
		map[string]any{"app": asc.Ref("apps", appID)}); err != nil {
		fatalf("add macOS to the app: %v", err)
	}
	step("added macOS to the app record")
}

// ensureInstallerCert returns the SHA-1 of a team Mac Installer Distribution
// certificate whose key is in the keychain, importing or creating installerP12.
func ensureInstallerCert(env *Env, c *asc.Client) string {
	certs, err := c.List("/v1/certificates?filter[certificateType]=MAC_INSTALLER_DISTRIBUTION&limit=50")
	if err != nil {
		fatalf("certificates: %v", err)
	}
	var team []string
	for _, ct := range certs {
		exp, _ := time.Parse(time.RFC3339, ct.Str("expirationDate"))
		der, err := base64.StdEncoding.DecodeString(ct.Str("certificateContent"))
		if err != nil || exp.Before(time.Now()) {
			continue
		}
		sum := sha1.Sum(der)
		team = append(team, strings.ToUpper(hex.EncodeToString(sum[:])))
	}
	find := func() string {
		local := output("security", "find-identity", "-v")
		for _, t := range team {
			if strings.Contains(local, t) {
				return t
			}
		}
		return ""
	}
	if id := find(); id != "" {
		return id
	}
	if _, err := os.Stat(installerP12); err != nil {
		if os.Getenv("CI") != "" {
			fatalf("%s is missing; run make gh-secrets", installerP12)
		}
		pass := newCertP12(c, "MAC_INSTALLER_DISTRIBUTION", "NoMax Mac Installer", installerP12)
		env.Set("MAC_INSTALLER_P12_PASSWORD", pass)
		env.Save()
		return ensureInstallerCert(env, c)
	}
	importP12(installerP12, env.Get("MAC_INSTALLER_P12_PASSWORD"))
	if id := find(); id != "" {
		return id
	}
	fatalf("%s does not match a team Mac Installer Distribution certificate", installerP12)
	return ""
}

// cmdMacDev builds a development copy of the Mac app (registering this Mac) and opens it.
func cmdMacDev(env *Env, _ []string) {
	run("bash", "-c", "cd apple && xcodegen generate --quiet")
	dd := "apple/build/macdev"
	step("building the Mac app")
	run("xcodebuild", "-project", "apple/NoMax.xcodeproj", "-scheme", "NoMaxMac", "-configuration", "Debug",
		"-destination", "platform=macOS", "-derivedDataPath", dd, "-quiet", "build", "NOMAX_HOST="+env.Must("DOMAIN"),
		"-allowProvisioningUpdates", "-allowProvisioningDeviceRegistration",
		"-authenticationKeyPath", mustAbs(filepath.Join("_cert", env.Must("ASC_KEY_FILE"))),
		"-authenticationKeyID", env.Must("ASC_KEY_ID"),
		"-authenticationKeyIssuerID", env.Must("ASC_ISSUER_ID"))
	run("open", filepath.Join(dd, "Build/Products/Debug/NoMax.app"))
}
