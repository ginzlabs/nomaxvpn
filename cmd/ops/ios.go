package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ginzlabs/nomaxvpn/internal/asc"
	"github.com/ginzlabs/nomaxvpn/internal/profile"
)

const (
	teamID     = "YOUR_TEAM_ID"
	appBundle  = "com.example.nomax"
	tunBundle  = "com.example.nomax.tunnel"
	betaGroup  = "Testers"
	distP12    = "_cert/apple-distribution.p12"
	iosDir     = "apple"
	archiveDir = "apple/build/release"
)

// caps are App ID capabilities; ents are what their profiles must then contain.
var bundles = []struct {
	id, name, target string
	caps, ents       []string
}{
	{appBundle, "NoMax", "NoMax", []string{"NETWORK_EXTENSIONS", "PERSONAL_VPN"}, []string{"packet-tunnel-provider", "com.apple.developer.networking.vpn.api"}},
	{tunBundle, "NoMax Tunnel", "NoMaxTunnel", []string{"NETWORK_EXTENSIONS"}, []string{"packet-tunnel-provider"}},
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func hasAll(s string, subs []string) bool {
	return !slices.ContainsFunc(subs, func(sub string) bool { return !strings.Contains(s, sub) })
}

func ascClient(env *Env) *asc.Client {
	p8, err := os.ReadFile(filepath.Join("_cert", env.Must("ASC_KEY_FILE")))
	if err != nil {
		fatalf("%v", err)
	}
	c, err := asc.New(env.Must("ASC_KEY_ID"), env.Must("ASC_ISSUER_ID"), p8)
	if err != nil {
		fatalf("%v", err)
	}
	return c
}

func bundleResource(c *asc.Client, identifier string) (asc.Resource, bool) {
	list, err := c.List("/v1/bundleIds?limit=50&filter[identifier]=" + url.QueryEscape(identifier))
	if err != nil {
		fatalf("bundle ids: %v", err)
	}
	for _, b := range list {
		if b.Str("identifier") == identifier {
			return b, true
		}
	}
	return asc.Resource{}, false
}

func findApp(c *asc.Client) (asc.Resource, bool) {
	apps, err := c.List("/v1/apps?filter[bundleId]=" + appBundle)
	if err != nil {
		fatalf("apps: %v", err)
	}
	for _, a := range apps {
		if a.Str("bundleId") == appBundle {
			return a, true
		}
	}
	return asc.Resource{}, false
}

// cmdIOSSetup registers bundle IDs and capabilities, then (once the app record
// exists) configures TestFlight: test info, beta review details, the testers' group.
func cmdIOSSetup(env *Env, _ []string) {
	c := ascClient(env)
	for _, b := range bundles {
		res, ok := bundleResource(c, b.id)
		if !ok {
			var err error
			res, err = c.Create("/v1/bundleIds", "bundleIds", map[string]any{"identifier": b.id, "name": b.name, "platform": "IOS"}, nil)
			if err != nil {
				fatalf("register %s: %v", b.id, err)
			}
			step("registered %s", b.id)
		}
		caps, err := c.List("/v1/bundleIds/" + res.ID + "/bundleIdCapabilities")
		if err != nil {
			fatalf("capabilities: %v", err)
		}
		for _, want := range b.caps {
			if slices.ContainsFunc(caps, func(cp asc.Resource) bool { return cp.Str("capabilityType") == want }) {
				continue
			}
			if _, err := c.Create("/v1/bundleIdCapabilities", "bundleIdCapabilities",
				map[string]any{"capabilityType": want},
				map[string]any{"bundleId": asc.Ref("bundleIds", res.ID)}); err != nil {
				fatalf("enable %s on %s: %v", want, b.id, err)
			}
			step("enabled %s on %s", want, b.id)
		}
	}

	app, ok := findApp(c)
	if !ok {
		fmt.Printf(`
One manual step: App Store Connect cannot create apps through its API.
  https://appstoreconnect.apple.com/apps  ->  "+"  ->  New App
  Platform iOS, Name "NoMax", Language English (UK), Bundle ID %s, SKU nomax, Full Access.
Then run: make ios-setup
`, appBundle)
		return
	}
	env.Set("ASC_APP_ID", app.ID)
	step("app record %s", app.ID)

	host := env.Must("DOMAIN")
	email := env.Get("FEEDBACK_EMAIL")
	locs, _ := c.List("/v1/apps/" + app.ID + "/betaAppLocalizations")
	locAttrs := map[string]any{
		"description":      "NoMax keeps your connection private and working on any network. Enter the PIN you were given, then tap the power button.",
		"privacyPolicyUrl": "https://" + host + "/" + env.Must("PRIVACY_PATH"),
		"marketingUrl":     "https://" + host + "/",
	}
	if email != "" {
		locAttrs["feedbackEmail"] = email
	}
	if len(locs) == 0 {
		locAttrs["locale"] = "en-GB"
		if _, err := c.Create("/v1/betaAppLocalizations", "betaAppLocalizations", locAttrs, map[string]any{"app": asc.Ref("apps", app.ID)}); err != nil {
			fmt.Fprintf(os.Stderr, "ops: beta test info: %v\n", err)
		}
	} else if err := c.Update("/v1/betaAppLocalizations/"+locs[0].ID, "betaAppLocalizations", locs[0].ID, locAttrs); err != nil {
		fmt.Fprintf(os.Stderr, "ops: beta test info: %v\n", err)
	}

	review := map[string]any{
		"demoAccountRequired": true,
		"demoAccountName":     "Invite PIN (no account)",
		"demoAccountPassword": env.Must("REVIEW_CODE"),
		"notes": "NoMax is a private VPN for a small group of people its admin invites; it is not a commercial service. Members join with a PIN from the admin instead of an account.\n" +
			"1. Launch the app and enter the PIN " + env.Must("REVIEW_CODE") + " (shown as the demo password), tap Join.\n" +
			"2. Allow the VPN configuration when iOS asks.\n3. Tap the power button to connect.",
	}
	if email != "" {
		review["contactEmail"] = email
	}
	contact := teamReviewContact(c, app.ID)
	for _, k := range []string{"REVIEW_FIRST_NAME:contactFirstName", "REVIEW_LAST_NAME:contactLastName", "REVIEW_PHONE:contactPhone"} {
		ek, ak, _ := strings.Cut(k, ":")
		if v := env.Get(ek); v != "" {
			review[ak] = v
		} else if v := contact[ak]; v != "" {
			review[ak] = v
		}
	}
	if err := c.Update("/v1/betaAppReviewDetails/"+app.ID, "betaAppReviewDetails", app.ID, review); err != nil {
		fmt.Fprintf(os.Stderr, "ops: beta review details: %v\n", err)
	}

	group := testerGroup(c, app.ID)
	if link := group.Str("publicLink"); link != "" {
		env.Set("TESTFLIGHT_URL", link)
		step("TestFlight link %s", link)
	}
	if err := env.Save(); err != nil {
		fatalf("%v", err)
	}
	step("App Store Connect is set up; next: make testflight")
}

func testerGroup(c *asc.Client, appID string) asc.Resource {
	groups, err := c.List("/v1/apps/" + appID + "/betaGroups")
	if err != nil {
		fatalf("beta groups: %v", err)
	}
	for _, g := range groups {
		if g.Str("name") == betaGroup {
			if g.Attributes["publicLinkEnabled"] != true {
				c.Update("/v1/betaGroups/"+g.ID, "betaGroups", g.ID, map[string]any{"publicLinkEnabled": true, "publicLinkLimitEnabled": false})
				var out struct{ Data asc.Resource }
				c.Do("GET", "/v1/betaGroups/"+g.ID, nil, &out)
				return out.Data
			}
			return g
		}
	}
	g, err := c.Create("/v1/betaGroups", "betaGroups", map[string]any{
		"name": betaGroup, "publicLinkEnabled": true, "publicLinkLimitEnabled": false, "feedbackEnabled": true,
	}, map[string]any{"app": asc.Ref("apps", appID)})
	if err != nil {
		fatalf("create beta group: %v", err)
	}
	step("created external TestFlight group %q", betaGroup)
	return g
}

// teamReviewContact borrows the review contact from another app on the team
// (its beta review details, or an App Store version's review details).
func teamReviewContact(c *asc.Client, skipID string) map[string]string {
	apps, err := c.List("/v1/apps?limit=200")
	if err != nil {
		return nil
	}
	contact := func(path string) map[string]string {
		var d struct{ Data asc.Resource }
		if c.Do("GET", path, nil, &d) != nil || d.Data.Str("contactPhone") == "" {
			return nil
		}
		out := map[string]string{}
		for _, k := range []string{"contactFirstName", "contactLastName", "contactPhone"} {
			out[k] = d.Data.Str(k)
		}
		return out
	}
	for _, a := range apps {
		if a.ID == skipID {
			continue
		}
		if out := contact("/v1/apps/" + a.ID + "/betaAppReviewDetail"); out != nil {
			return out
		}
		versions, _ := c.List("/v1/apps/" + a.ID + "/appStoreVersions?limit=5")
		for _, v := range versions {
			if out := contact("/v1/appStoreVersions/" + v.ID + "/appStoreReviewDetail"); out != nil {
				return out
			}
		}
	}
	return nil
}

// setWhatsNew fills the build's en-GB "What to Test"; Apple often creates the localization itself.
func setWhatsNew(c *asc.Client, buildID, text string) error {
	locs, err := c.List("/v1/builds/" + buildID + "/betaBuildLocalizations")
	if err != nil {
		return err
	}
	for _, l := range locs {
		if l.Str("locale") == "en-GB" {
			return c.Update("/v1/betaBuildLocalizations/"+l.ID, "betaBuildLocalizations", l.ID, map[string]any{"whatsNew": text})
		}
	}
	_, err = c.Create("/v1/betaBuildLocalizations", "betaBuildLocalizations", map[string]any{"locale": "en-GB", "whatsNew": text},
		map[string]any{"build": asc.Ref("builds", buildID)})
	return err
}

type teamCert struct{ id, sha1 string }

type signing struct {
	identity string
	profiles map[string]string // bundle id -> profile UUID
}

// cmdIOSSigning makes sure App Store profiles exist for the app and tunnel,
// signed by a team Distribution certificate whose key is in the local keychain.
func cmdIOSSigning(env *Env, _ []string) {
	c := ascClient(env)
	ensureSigning(env, c, false)
	ensureSigning(env, c, true)
}

// cmdIOSCICert creates a dedicated Apple Distribution certificate for CI and
// stores it with its key as distP12. Apple caps distribution certs per team, so
// it refuses when the team already has two unless -force is given.
func cmdIOSCICert(env *Env, args []string) {
	if _, err := os.Stat(distP12); err == nil {
		step("%s already exists", distP12)
		return
	}
	c := ascClient(env)
	certs, err := c.List("/v1/certificates?filter[certificateType]=DISTRIBUTION&limit=200")
	if err != nil {
		fatalf("certificates: %v", err)
	}
	for _, ct := range certs {
		fmt.Printf("  existing: %s (expires %s)\n", ct.Str("displayName"), ct.Str("expirationDate"))
	}
	if len(certs) >= 2 && !slices.Contains(args, "-force") {
		fatalf("team already has %d distribution certificates; export one to %s instead, or rerun with -force", len(certs), distP12)
	}

	pass := newCertP12(c, "DISTRIBUTION", "NoMax CI", distP12)
	env.Set("DIST_P12_PASSWORD", pass)
	env.Save()
	step("wrote %s; run make gh-secrets", distP12)
}

func ensureSigning(env *Env, c *asc.Client, mac bool) signing {
	certs, err := c.List("/v1/certificates?filter[certificateType]=DISTRIBUTION&limit=200")
	if err != nil {
		fatalf("certificates: %v", err)
	}
	var team []teamCert
	for _, ct := range certs {
		exp, _ := time.Parse(time.RFC3339, ct.Str("expirationDate"))
		der, err := base64.StdEncoding.DecodeString(ct.Str("certificateContent"))
		if err != nil || exp.Before(time.Now()) {
			continue
		}
		sum := sha1.Sum(der)
		team = append(team, teamCert{ct.ID, strings.ToUpper(hex.EncodeToString(sum[:]))})
	}
	find := func() *teamCert {
		local := output("security", "find-identity", "-v", "-p", "codesigning")
		for _, t := range team {
			if strings.Contains(local, t.sha1) {
				return &t
			}
		}
		return nil
	}
	cert := find()
	if cert == nil {
		if _, err := os.Stat(distP12); err == nil {
			importP12(distP12, env.Get("DIST_P12_PASSWORD"))
			cert = find()
		}
	}
	if cert == nil {
		fatalf("no team Apple Distribution certificate has its key in this keychain (export one to %s for CI)", distP12)
	}

	dir := filepath.Join(os.Getenv("HOME"), "Library/Developer/Xcode/UserData/Provisioning Profiles")
	os.MkdirAll(dir, 0o755)
	s := signing{identity: cert.sha1, profiles: map[string]string{}}
	for _, b := range bundles {
		res, ok := bundleResource(c, b.id)
		if !ok {
			fatalf("%s is not registered; run make ios-setup", b.id)
		}
		name, profileType, ext := "NoMax "+b.id+" AppStore", "IOS_APP_STORE", ".mobileprovision"
		if mac {
			name, profileType, ext = "NoMax "+b.id+" MacAppStore", "MAC_APP_STORE", ".provisionprofile"
		}
		existing, err := c.List("/v1/bundleIds/" + res.ID + "/profiles?limit=200")
		if err != nil {
			fatalf("profiles: %v", err)
		}
		var prof *asc.Resource
		for i := range existing {
			p := existing[i]
			if p.Str("name") != name {
				continue
			}
			exp, _ := time.Parse(time.RFC3339, p.Str("expirationDate"))
			content, _ := base64.StdEncoding.DecodeString(p.Str("profileContent"))
			usable := p.Str("profileState") == "ACTIVE" && exp.After(time.Now().Add(7*24*time.Hour)) &&
				hasAll(string(content), b.ents) && profileHasCerts(c, p.ID, team)
			if usable && prof == nil {
				prof = &p
			} else {
				c.Do("DELETE", "/v1/profiles/"+p.ID, nil, nil)
			}
		}
		if prof == nil {
			// Every team distribution cert, so local and CI builds share one profile.
			refs := make([]any, len(team))
			for i, t := range team {
				refs[i] = asc.Ref("certificates", t.id)
			}
			p, err := c.Create("/v1/profiles", "profiles", map[string]any{"name": name, "profileType": profileType}, map[string]any{
				"bundleId":     asc.Ref("bundleIds", res.ID),
				"certificates": refs,
			})
			if err != nil {
				fatalf("create profile %s: %v", name, err)
			}
			prof = &p
			step("created profile %q", name)
		}
		content, _ := base64.StdEncoding.DecodeString(prof.Str("profileContent"))
		if !hasAll(string(content), b.ents) {
			fatalf("profile %q lacks %v; run make ios-setup", name, b.ents)
		}
		uuid := prof.Str("uuid")
		if err := os.WriteFile(filepath.Join(dir, uuid+ext), content, 0o644); err != nil {
			fatalf("%v", err)
		}
		s.profiles[b.id] = uuid
	}
	step("signing: identity %s…, profiles installed", s.identity[:8])
	return s
}

func profileHasCerts(c *asc.Client, profileID string, want []teamCert) bool {
	certs, err := c.List("/v1/profiles/" + profileID + "/certificates?limit=50")
	if err != nil {
		return false
	}
	have := map[string]bool{}
	for _, x := range certs {
		have[x.ID] = true
	}
	for _, w := range want {
		if !have[w.id] {
			return false
		}
	}
	return true
}

func marketingVersion() string {
	b, err := os.ReadFile(filepath.Join(iosDir, "project.yml"))
	if err != nil {
		fatalf("%v", err)
	}
	m := regexp.MustCompile(`MARKETING_VERSION:\s*"?([0-9.]+)"?`).FindSubmatch(b)
	if m == nil {
		fatalf("MARKETING_VERSION not found in apple/project.yml")
	}
	return string(m[1])
}

// cmdTestFlight archives, uploads, waits for processing, and hands the build to the testers' group.
// -no-upload stops after a signed export (works before the app record exists); -mac ships the Mac app.
func cmdTestFlight(env *Env, args []string) {
	upload := !slices.Contains(args, "-no-upload")
	mac := slices.Contains(args, "-mac")
	c := ascClient(env)
	app, ok := findApp(c)
	if !ok && upload {
		fatalf("no app record for %s; run make ios-setup", appBundle)
	}
	next := 1
	if ok {
		builds, err := c.List("/v1/builds?filter[app]=" + app.ID + "&sort=-uploadedDate&limit=200&fields[builds]=version")
		if err != nil {
			fatalf("builds: %v", err)
		}
		var numbers []string
		for _, b := range builds {
			numbers = append(numbers, b.Str("version"))
		}
		// An upload Apple is still processing isn't a build yet, but its number is taken.
		uploads, _ := c.List("/v1/apps/" + app.ID + "/buildUploads?limit=200")
		for _, u := range uploads {
			numbers = append(numbers, u.Str("cfBundleVersion"))
		}
		for _, v := range numbers {
			if n, err := strconv.Atoi(v); err == nil && n >= next {
				next = n + 1
			}
		}
	}
	if n, err := strconv.Atoi(os.Getenv("BUILD_NUMBER")); err == nil && n > next {
		next = n
	}
	version := marketingVersion()
	build := strconv.Itoa(next)
	scheme, platform, target := "NoMax", "iOS", func(t string) string { return t }
	if mac {
		scheme, platform, target = "NoMaxMac", "macOS", func(t string) string { return strings.Replace(t, "NoMax", "NoMaxMac", 1) }
		if ok {
			ensureMacPlatform(c, app.ID, version)
		}
	}
	step("%s %s (%s)", scheme, version, build)

	s := ensureSigning(env, c, mac)
	installer := ""
	if mac {
		installer = ensureInstallerCert(env, c)
	}
	run("bash", "-c", "cd apple && xcodegen generate --quiet")

	os.MkdirAll(archiveDir, 0o755)
	archive := filepath.Join(archiveDir, scheme+"-"+build+".xcarchive")
	exportDir := filepath.Join(archiveDir, scheme+"-"+build)
	os.RemoveAll(archive)
	os.RemoveAll(exportDir)
	xb := []string{
		"-project", "apple/NoMax.xcodeproj", "-scheme", scheme, "-configuration", "Release",
		"-destination", "generic/platform=" + platform, "-archivePath", archive, "archive", "-quiet",
		"CURRENT_PROJECT_VERSION=" + build, "MARKETING_VERSION=" + version, "NOMAX_HOST=" + env.Must("DOMAIN"),
		"CODE_SIGN_STYLE=Manual", "DEVELOPMENT_TEAM=" + teamID, "CODE_SIGN_IDENTITY=" + s.identity,
	}
	for _, b := range bundles {
		xb = append(xb, "NOMAX_PROFILE_"+target(b.target)+"="+s.profiles[b.id])
	}
	xb = append(xb, "PROVISIONING_PROFILE_SPECIFIER=$(NOMAX_PROFILE_$(TARGET_NAME))")
	step("archiving")
	run("xcodebuild", xb...)

	var profiles strings.Builder
	for id, uuid := range s.profiles {
		fmt.Fprintf(&profiles, "    <key>%s</key><string>%s</string>\n", id, uuid)
	}
	opts := filepath.Join(archiveDir, "ExportOptions.plist")
	os.WriteFile(opts, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>`+map[bool]string{true: "upload", false: "export"}[upload]+`</string>
  <key>teamID</key><string>`+teamID+`</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>`+s.identity+`</string>
`+map[bool]string{true: "  <key>installerSigningCertificate</key><string>" + installer + "</string>\n"}[mac]+`  <key>provisioningProfiles</key>
  <dict>
`+profiles.String()+`  </dict>
  <key>manageAppVersionAndBuildNumber</key><false/>
  <key>uploadSymbols</key><true/>
  <key>testFlightInternalTestingOnly</key><false/>
</dict>
</plist>
`), 0o644)
	if upload {
		step("uploading to App Store Connect")
	} else {
		step("exporting")
	}
	run("xcodebuild", "-exportArchive", "-archivePath", archive, "-exportPath", exportDir, "-exportOptionsPlist", opts,
		"-allowProvisioningUpdates",
		"-authenticationKeyPath", mustAbs(filepath.Join("_cert", env.Must("ASC_KEY_FILE"))),
		"-authenticationKeyID", env.Must("ASC_KEY_ID"),
		"-authenticationKeyIssuerID", env.Must("ASC_ISSUER_ID"))
	if !upload {
		step("signed export in %s", exportDir)
		return
	}

	buildRes := waitForBuild(c, app.ID, build, map[bool]string{false: "IOS", true: "MAC_OS"}[mac])
	if buildRes.Attributes["usesNonExemptEncryption"] == nil {
		c.Update("/v1/builds/"+buildRes.ID, "builds", buildRes.ID, map[string]any{"usesNonExemptEncryption": false})
	}
	whatsNew := strings.TrimSpace(os.Getenv("WHATS_NEW"))
	if whatsNew == "" {
		whatsNew = strings.TrimSpace(outputOr("git", "log", "-1", "--pretty=%s"))
	}
	if whatsNew != "" {
		if err := setWhatsNew(c, buildRes.ID, whatsNew); err != nil {
			fmt.Fprintf(os.Stderr, "ops: what's new: %v\n", err)
		}
	}
	if slices.Contains(args, "-review") {
		submitBetaReview(c, app.ID, buildRes)
	} else {
		step("build %s is uploaded; once it's tested, make beta-review hands it to the %s group", build, betaGroup)
	}
}

// cmdBetaReview hands the newest processed build to the testers' group and
// Apple's beta review, which external testers need. Run it after testing.
func cmdBetaReview(env *Env, args []string) {
	c := ascClient(env)
	app, ok := findApp(c)
	if !ok {
		fatalf("no app record for %s; run make ios-setup", appBundle)
	}
	platform := "IOS"
	if slices.Contains(args, "-mac") {
		platform = "MAC_OS"
	}
	builds, err := c.List("/v1/builds?filter[app]=" + app.ID + "&filter[preReleaseVersion.platform]=" + platform +
		"&filter[processingState]=VALID&filter[expired]=false&sort=-uploadedDate&limit=1")
	if err != nil {
		fatalf("builds: %v", err)
	}
	if len(builds) == 0 {
		fatalf("no processed %s build; run make testflight", platform)
	}
	submitBetaReview(c, app.ID, builds[0])
}

func submitBetaReview(c *asc.Client, appID string, b asc.Resource) {
	group := testerGroup(c, appID)
	if err := c.Do("POST", "/v1/betaGroups/"+group.ID+"/relationships/builds", map[string]any{"data": []any{asc.Ref("builds", b.ID)}}, nil); err != nil {
		fatalf("add build to %s: %v", betaGroup, err)
	}
	if _, err := c.Create("/v1/betaAppReviewSubmissions", "betaAppReviewSubmissions", nil, map[string]any{"build": asc.Ref("builds", b.ID)}); err != nil {
		fmt.Fprintf(os.Stderr, "ops: beta review submission: %v (a previous build may already be approved or in review)\n", err)
	} else {
		step("submitted build %s for TestFlight beta review", b.Str("version"))
	}
	if link := group.Str("publicLink"); link != "" {
		step("testers join at %s", link)
	}
}

func waitForBuild(c *asc.Client, appID, build, platform string) asc.Resource {
	step("waiting for Apple to process build %s", build)
	deadline := time.Now().Add(60 * time.Minute)
	for time.Now().Before(deadline) {
		list, err := c.List("/v1/builds?filter[app]=" + appID + "&filter[version]=" + build + "&filter[preReleaseVersion.platform]=" + platform + "&limit=5")
		if err == nil && len(list) > 0 {
			switch st := list[0].Str("processingState"); st {
			case "VALID":
				return list[0]
			case "FAILED", "INVALID":
				fatalf("build %s processing %s", build, st)
			}
		}
		time.Sleep(30 * time.Second)
	}
	fatalf("build %s still processing after an hour", build)
	return asc.Resource{}
}

// cmdIOSDevice builds a development copy and installs it on the connected iPhone.
func cmdIOSDevice(env *Env, _ []string) {
	udid := connectedIPhone()
	run("bash", "-c", "cd apple && xcodegen generate --quiet")
	dd := "apple/build/dev"
	step("building for %s", udid)
	run("xcodebuild", "-project", "apple/NoMax.xcodeproj", "-scheme", "NoMax", "-configuration", "Debug",
		"-destination", "id="+udid, "-derivedDataPath", dd, "-quiet", "build", "NOMAX_HOST="+env.Must("DOMAIN"),
		"-allowProvisioningUpdates", "-allowProvisioningDeviceRegistration",
		"-authenticationKeyPath", mustAbs(filepath.Join("_cert", env.Must("ASC_KEY_FILE"))),
		"-authenticationKeyID", env.Must("ASC_KEY_ID"),
		"-authenticationKeyIssuerID", env.Must("ASC_ISSUER_ID"))
	run("xcrun", "devicectl", "device", "install", "app", "--device", udid, filepath.Join(dd, "Build/Products/Debug-iphoneos/NoMax.app"))
	run("xcrun", "devicectl", "device", "process", "launch", "--device", udid, appBundle)
}

// connectedIPhone returns the UDID of the one paired iPhone that is reachable
// now, or $IPHONE when several are.
func connectedIPhone() string {
	if udid := os.Getenv("IPHONE"); udid != "" {
		return udid
	}
	f, err := os.CreateTemp("", "devices-*.json")
	if err != nil {
		fatalf("%v", err)
	}
	f.Close()
	defer os.Remove(f.Name())
	if err := exec.Command("xcrun", "devicectl", "list", "devices", "--json-output", f.Name()).Run(); err != nil {
		fatalf("devicectl: %v", err)
	}
	var out struct {
		Result struct {
			Devices []struct {
				Connection struct{ PairingState, TunnelState string } `json:"connectionProperties"`
				Hardware   struct{ DeviceType, Reality, UDID string } `json:"hardwareProperties"`
			} `json:"devices"`
		} `json:"result"`
	}
	b, _ := os.ReadFile(f.Name())
	if err := json.Unmarshal(b, &out); err != nil {
		fatalf("devicectl output: %v", err)
	}
	var found []string
	for _, d := range out.Result.Devices {
		if d.Hardware.DeviceType == "iPhone" && d.Hardware.Reality == "physical" &&
			d.Connection.PairingState == "paired" && d.Connection.TunnelState != "unavailable" {
			found = append(found, d.Hardware.UDID)
		}
	}
	if len(found) != 1 {
		fatalf("want exactly one reachable iPhone, found %d: %s (unlock it and keep it on the same Wi-Fi or cable, or pick one with IPHONE=<udid>)",
			len(found), strings.Join(found, ", "))
	}
	return found[0]
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		fatalf("%v", err)
	}
	return a
}

func outputOr(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// newCertP12 creates a certificate of certType from a fresh key and writes both
// to path as a PKCS#12, returning its password.
func newCertP12(c *asc.Client, certType, name, path string) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("%v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name, Organization: []string{"NoMax"}},
	}, key)
	if err != nil {
		fatalf("%v", err)
	}
	ct, err := c.Create("/v1/certificates", "certificates", map[string]any{
		"certificateType": certType,
		"csrContent":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
	}, nil)
	if err != nil {
		fatalf("create certificate: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(ct.Str("certificateContent"))
	if err != nil {
		fatalf("certificate content: %v", err)
	}
	step("created %s (expires %s)", ct.Str("displayName"), ct.Str("expirationDate"))

	tmp, err := os.MkdirTemp("", "nomax-cert")
	if err != nil {
		fatalf("%v", err)
	}
	defer os.RemoveAll(tmp)
	keyFile, certFile := filepath.Join(tmp, "key.pem"), filepath.Join(tmp, "cert.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	pass := profile.RandomHex(16)
	// LibreSSL's PKCS#12 defaults (3DES, SHA-1 MAC) are what `security import` accepts.
	cmd := exec.Command("/usr/bin/openssl", "pkcs12", "-export", "-inkey", keyFile, "-in", certFile,
		"-name", name, "-out", path, "-passout", "env:P12_PASS")
	cmd.Env = append(os.Environ(), "P12_PASS="+pass)
	if out, err := cmd.CombinedOutput(); err != nil {
		fatalf("openssl pkcs12: %v\n%s", err, out)
	}
	os.Chmod(path, 0o600)
	return pass
}

// importP12 adds a PKCS#12 to $KEYCHAIN (CI) or the login keychain.
func importP12(path, pass string) {
	step("importing %s", path)
	kc := os.Getenv("KEYCHAIN")
	if kc == "" {
		kc = filepath.Join(os.Getenv("HOME"), "Library/Keychains/login.keychain-db")
	}
	run("security", "import", path, "-k", kc, "-f", "pkcs12", "-P", pass, "-T", "/usr/bin/codesign", "-T", "/usr/bin/security", "-T", "/usr/bin/productbuild")
}
